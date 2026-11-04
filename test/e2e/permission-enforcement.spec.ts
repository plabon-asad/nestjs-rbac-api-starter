import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import {
  createPermissionFixture,
  createRoleFixture,
  createUserFixture,
  grantRole,
} from '../utils/rbac-fixtures.js';
import { routeClient, type RouteClient } from '../utils/route-client.js';
import { createTestApp, type TestContext } from '../utils/create-test-app.js';

const PASSWORD = 'enforcement-password-123';
const MANAGED_KEYS = [
  'roles.read',
  'roles.create',
  'roles.update',
  'roles.delete',
  'permissions.read',
  'audit-logs.read',
];

let ctx: TestContext;

async function tokenFor(email: string): Promise<string> {
  const res = await request(ctx.app.getHttpServer())
    .post('/api/auth/login')
    .send({ email, password: PASSWORD })
    .expect(200);
  return res.body.accessToken as string;
}

async function actingAs(email: string, role: string): Promise<RouteClient> {
  const userId = await createUserFixture(email, { password: PASSWORD });
  await grantRole(userId, role);
  return routeClient(ctx.app, await tokenFor(email));
}

beforeAll(async () => {
  ctx = await createTestApp();
});

beforeEach(async () => {
  await resetTestDatabase();
  for (const key of MANAGED_KEYS) {
    await createPermissionFixture(key);
  }
  await createRoleFixture('READ_ONLY', ['roles.read']);
  await createRoleFixture('ROLE_ADMIN', [
    'roles.read',
    'roles.create',
    'roles.update',
    'permissions.read',
  ]);
  await createRoleFixture('SUPER_ADMIN', [], true);
});

afterAll(async () => {
  await ctx.app.close();
});

describe('PermissionsGuard', () => {
  it('allows the granted read and refuses the ungranted one', async () => {
    const api = await actingAs('reader@enforce.test.local', 'READ_ONLY');

    await api.get('/api/roles').expect(200);
    await api.get('/api/permissions').expect(403);
  });

  it('refuses writes the caller has no grant for', async () => {
    const api = await actingAs('reader2@enforce.test.local', 'READ_ONLY');

    await api.post('/api/roles').send({ name: 'Sneaky', permissionKeys: [] }).expect(403);
    await api.delete('/api/roles/whatever-id').expect(403);
  });

  it('grants a system-role holder everything without a single permission row', async () => {
    const api = await actingAs('root@enforce.test.local', 'SUPER_ADMIN');

    await api.get('/api/permissions').expect(200);
    const created = await api
      .post('/api/roles')
      .send({ name: 'Root-Created', permissionKeys: ['audit-logs.read'] })
      .expect(201);
    await api.delete(`/api/roles/${created.body.id}`).expect(204);
  });

  it('keeps self-service auth routes available with no permission at all', async () => {
    const api = await actingAs('self@enforce.test.local', 'READ_ONLY');

    await api.get('/api/auth/me').expect(200);
    await api
      .post('/api/auth/change-password')
      .send({ currentPassword: PASSWORD, newPassword: 'rotated-password-123' })
      .expect(204);
  });

  it('leaves public routes reachable without a token', async () => {
    await request(ctx.app.getHttpServer())
      .post('/api/auth/forgot-password')
      .send({ email: 'nobody@enforce.test.local' })
      .expect(202);
  });

  it('applies a permission revocation to the next request on the same token', async () => {
    const api = await actingAs('revoke@enforce.test.local', 'READ_ONLY');
    await api.get('/api/roles').expect(200);

    await prisma.rolePermission.deleteMany({ where: { role: { name: 'READ_ONLY' } } });
    await api.get('/api/roles').expect(403);
  });

  it('applies a role removal to the next request', async () => {
    const userId = await createUserFixture('demote@enforce.test.local', { password: PASSWORD });
    await grantRole(userId, 'READ_ONLY');
    const api = routeClient(ctx.app, await tokenFor('demote@enforce.test.local'));

    await api.get('/api/roles').expect(200);
    await prisma.userRole.deleteMany({ where: { userId } });
    await api.get('/api/roles').expect(403);
  });

  it('refuses an inactive account even while its access token is still valid', async () => {
    const userId = await createUserFixture('off@enforce.test.local', { password: PASSWORD });
    await grantRole(userId, 'READ_ONLY');
    const api = routeClient(ctx.app, await tokenFor('off@enforce.test.local'));

    await api.get('/api/roles').expect(200);
    await prisma.user.update({ where: { id: userId }, data: { status: 'DISABLED' } });
    await api.get('/api/roles').expect(403);
  });
});

describe('grant-scope enforcement', () => {
  it('refuses to hand out a permission the caller does not hold', async () => {
    const api = await actingAs('scope@enforce.test.local', 'ROLE_ADMIN');

    await api
      .post('/api/roles')
      .send({ name: 'Overreacher', permissionKeys: ['audit-logs.read'] })
      .expect(403);
    await expect(prisma.role.findUnique({ where: { name: 'Overreacher' } })).resolves.toBeNull();
  });

  it('allows granting permissions the caller already holds', async () => {
    const api = await actingAs('ok@enforce.test.local', 'ROLE_ADMIN');

    await api
      .post('/api/roles')
      .send({ name: 'Scoped', permissionKeys: ['permissions.read'] })
      .expect(201);
  });

  it('blocks a later grant update that would exceed the caller', async () => {
    const api = await actingAs('later@enforce.test.local', 'ROLE_ADMIN');
    const created = await api
      .post('/api/roles')
      .send({ name: 'Expandable', permissionKeys: [] })
      .expect(201);

    await api
      .put(`/api/roles/${created.body.id}/permissions`)
      .send({ permissionKeys: ['roles.delete'] })
      .expect(403);
    await api
      .put(`/api/roles/${created.body.id}/permissions`)
      .send({ permissionKeys: ['roles.read'] })
      .expect(200);
  });

  it('lets a caller with no management permission create nothing at all', async () => {
    const api = await actingAs('plain@enforce.test.local', 'READ_ONLY');
    await api.post('/api/roles').send({ name: 'Impossible' }).expect(403);
  });
});
