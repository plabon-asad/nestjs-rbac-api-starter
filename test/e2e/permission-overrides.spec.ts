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

const PASSWORD = 'override-password-123';

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
  await createPermissionFixture('roles.read');
  await createPermissionFixture('audit-logs.read');
  await createPermissionFixture('permission-overrides.read');
  await createPermissionFixture('permission-overrides.manage');
  await createRoleFixture('READER', ['roles.read']);
  await createRoleFixture('OVERRIDE_MANAGER', [
    'permission-overrides.read',
    'permission-overrides.manage',
    'roles.read',
  ]);
  await createRoleFixture('SUPER_ADMIN', [], true);
});

afterAll(async () => {
  await ctx.app.close();
});

describe('override endpoints on the RBAC surface', () => {
  it('rejects unauthenticated calls', async () => {
    await request(ctx.app.getHttpServer()).get('/api/permission-overrides/any-user').expect(401);
    await request(ctx.app.getHttpServer())
      .put('/api/permission-overrides/any-user/roles.read')
      .send({ effect: 'DENY' })
      .expect(401);
  });

  it('refuses viewers who hold neither override permission', async () => {
    const api = await actingAs('plain@http.test.local', 'READER');
    await api.get('/api/permission-overrides/whatever').expect(403);
    await api
      .put('/api/permission-overrides/whatever/roles.read')
      .send({ effect: 'DENY' })
      .expect(403);
  });
});

describe('DENY, ALLOW and INHERIT over HTTP', () => {
  it('a DENY hides a role grant on the very next request and INHERIT restores it', async () => {
    const manager = await actingAs('manager@http.test.local', 'OVERRIDE_MANAGER');
    const target = await actingAs('target@http.test.local', 'READER');
    const targetId = await prisma.user.findUniqueOrThrow({
      where: { email: 'target@http.test.local' },
      select: { id: true },
    });

    await target.get('/api/roles').expect(200);
    await manager
      .put(`/api/permission-overrides/${targetId.id}/roles.read`)
      .send({ effect: 'DENY' })
      .expect(200);
    await target.get('/api/roles').expect(403);

    const listed = await manager.get(`/api/permission-overrides/${targetId.id}`).expect(200);
    expect(listed.body).toEqual([{ permissionKey: 'roles.read', effect: 'DENY' }]);

    await manager
      .put(`/api/permission-overrides/${targetId.id}/roles.read`)
      .send({ effect: 'INHERIT' })
      .expect(200);
    await target.get('/api/roles').expect(200);
  });

  it('an ALLOW grants access to a caller with no role at all', async () => {
    const manager = await actingAs('manager2@http.test.local', 'OVERRIDE_MANAGER');
    const lonely = await createUserFixture('lonely@http.test.local', { password: PASSWORD });
    const lonelyApi = routeClient(ctx.app, await tokenFor('lonely@http.test.local'));

    await lonelyApi.get('/api/roles').expect(403);
    await manager
      .put(`/api/permission-overrides/${lonely}/roles.read`)
      .send({ effect: 'ALLOW' })
      .expect(200);
    await lonelyApi.get('/api/roles').expect(200);
  });

  it('refuses to ALLOW a permission the actor does not hold (grant-scope over HTTP)', async () => {
    const manager = await actingAs('manager3@http.test.local', 'OVERRIDE_MANAGER');
    const target = await createUserFixture('target3@http.test.local', { password: PASSWORD });

    // The manager holds roles.read but not audit-logs.read, so only the second ALLOW is out of scope.
    await manager
      .put(`/api/permission-overrides/${target}/audit-logs.read`)
      .send({ effect: 'ALLOW' })
      .expect(403);
    await expect(prisma.userPermissionOverride.count({ where: { userId: target } })).resolves.toBe(
      0,
    );
  });

  it('protects the system role: nobody may override a super admin', async () => {
    const manager = await actingAs('manager4@http.test.local', 'OVERRIDE_MANAGER');
    const root = await createUserFixture('root4@http.test.local', { password: PASSWORD });
    await grantRole(root, 'SUPER_ADMIN');

    await manager
      .put(`/api/permission-overrides/${root}/roles.read`)
      .send({ effect: 'DENY' })
      .expect(403);
  });

  it('validates bodies, keys and users', async () => {
    const manager = await actingAs('manager5@http.test.local', 'OVERRIDE_MANAGER');
    const target = await createUserFixture('target5@http.test.local', { password: PASSWORD });

    await manager
      .put(`/api/permission-overrides/${target}/roles.read`)
      .send({ effect: 'MAYBE' })
      .expect(400);
    await manager
      .put(`/api/permission-overrides/${target}/ghost.read`)
      .send({ effect: 'ALLOW' })
      .expect(400);
    await manager
      .put('/api/permission-overrides/ghost-user/roles.read')
      .send({ effect: 'ALLOW' })
      .expect(404);
  });
});
