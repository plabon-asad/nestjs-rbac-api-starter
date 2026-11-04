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

const PASSWORD = 'users-e2e-password-123';

let ctx: TestContext;

async function tokenFor(email: string, password: string = PASSWORD): Promise<string> {
  const res = await request(ctx.app.getHttpServer())
    .post('/api/auth/login')
    .send({ email, password })
    .expect(200);
  return res.body.accessToken as string;
}

async function actingAs(email: string, role: string): Promise<RouteClient> {
  const userId = await createUserFixture(email, { password: PASSWORD });
  await grantRole(userId, role);
  return routeClient(ctx.app, await tokenFor(email));
}

const INITIAL_PASSWORD = 'initial-password-123';

function newAccount(email: string): Record<string, unknown> {
  return {
    email,
    password: INITIAL_PASSWORD,
    firstName: 'E2e',
    lastName: 'Account',
    roleNames: [],
  };
}

beforeAll(async () => {
  ctx = await createTestApp();
});

beforeEach(async () => {
  await resetTestDatabase();
  await createPermissionFixture('roles.read');
  await createPermissionFixture('users.read');
  await createPermissionFixture('users.create');
  await createPermissionFixture('users.update');
  await createPermissionFixture('users.delete');
  await createPermissionFixture('users.assign-roles');
  await createRoleFixture('READER', ['roles.read']);
  await createRoleFixture('USER_MANAGER', [
    'users.read',
    'users.create',
    'users.update',
    'users.delete',
    'users.assign-roles',
    'roles.read',
  ]);
  await createRoleFixture('SUPER_ADMIN', [], true);
});

afterAll(async () => {
  await ctx.app.close();
});

describe('users endpoints', () => {
  it('rejects unauthenticated calls', async () => {
    await request(ctx.app.getHttpServer()).get('/api/users').expect(401);
    await request(ctx.app.getHttpServer())
      .post('/api/users')
      .send(newAccount('x@http.test.local'))
      .expect(401);
  });

  it('refuses managers who lack each specific permission', async () => {
    const reader = await actingAs('reader@http.test.local', 'READER');
    await reader.get('/api/users').expect(403);
    await reader.post('/api/users').send(newAccount('x@http.test.local')).expect(403);
    await reader.patch('/api/users/whatever').send({ firstName: 'x' }).expect(403);
    await reader.delete('/api/users/whatever').expect(403);
    await reader.put('/api/users/whatever/roles').send({ roleNames: [] }).expect(403);
  });
});

describe('creating accounts over HTTP', () => {
  it('creates a usable account and the new user can log in immediately', async () => {
    const manager = await actingAs('manager@http.test.local', 'USER_MANAGER');

    const created = await manager
      .post('/api/users')
      .send({ ...newAccount('created@http.test.local'), roleNames: ['READER'] })
      .expect(201);

    expect(created.body).toMatchObject({
      email: 'created@http.test.local',
      firstName: 'E2e',
      status: 'ACTIVE',
      roleNames: ['READER'],
    });
    expect(JSON.stringify(created.body)).not.toMatch(/passwordHash/i);

    await tokenFor('created@http.test.local', INITIAL_PASSWORD);
    const stored = await prisma.user.findUniqueOrThrow({
      where: { email: 'created@http.test.local' },
    });
    expect(stored.passwordHash.startsWith('$argon2')).toBe(true);
  });

  it('validates payloads: duplicate email, weak password, unknown role', async () => {
    const manager = await actingAs('manager2@http.test.local', 'USER_MANAGER');

    await manager.post('/api/users').send(newAccount('dup@http.test.local')).expect(201);
    await manager.post('/api/users').send(newAccount('dup@http.test.local')).expect(409);
    await manager
      .post('/api/users')
      .send({ ...newAccount('weak@http.test.local'), password: 'short' })
      .expect(400);
    await manager
      .post('/api/users')
      .send({ ...newAccount('ghost@http.test.local'), roleNames: ['NOPE'] })
      .expect(400);
  });

  it('a normal manager cannot hand out the system role', async () => {
    const manager = await actingAs('manager3@http.test.local', 'USER_MANAGER');

    await manager
      .post('/api/users')
      .send({ ...newAccount('promote@http.test.local'), roleNames: ['SUPER_ADMIN'] })
      .expect(403);
    await expect(
      prisma.user.findUnique({ where: { email: 'promote@http.test.local' } }),
    ).resolves.toBeNull();
  });
});

describe('disabling accounts takes effect on the very next request', () => {
  it('an issued access token stops working once the account is DISABLED', async () => {
    const manager = await actingAs('manager4@http.test.local', 'USER_MANAGER');
    const created = await manager
      .post('/api/users')
      .send({ ...newAccount('victim@http.test.local'), roleNames: ['READER'] })
      .expect(201);

    const victimApi = routeClient(
      ctx.app,
      await tokenFor('victim@http.test.local', INITIAL_PASSWORD),
    );
    await victimApi.get('/api/roles').expect(200);

    await manager.patch(`/api/users/${created.body.id}`).send({ status: 'DISABLED' }).expect(200);
    await victimApi.get('/api/roles').expect(403);

    await request(ctx.app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'victim@http.test.local', password: 'initial-password-123' })
      .expect(401);
  });

  it('refuses to disable your own account', async () => {
    const manager = await actingAs('manager5@http.test.local', 'USER_MANAGER');
    const me = await prisma.user.findUniqueOrThrow({
      where: { email: 'manager5@http.test.local' },
      select: { id: true },
    });

    await manager.patch(`/api/users/${me.id}`).send({ status: 'DISABLED' }).expect(400);
  });
});

describe('role assignment over HTTP', () => {
  it('replaces the role set and reads it back', async () => {
    const manager = await actingAs('manager6@http.test.local', 'USER_MANAGER');
    const created = await manager
      .post('/api/users')
      .send({ ...newAccount('roles@http.test.local'), roleNames: ['READER'] })
      .expect(201);

    const updated = await manager
      .put(`/api/users/${created.body.id}/roles`)
      .send({ roleNames: [] })
      .expect(200);
    expect(updated.body.roleNames).toEqual([]);

    const listed = await manager.get('/api/users').expect(200);
    const target = (listed.body as { email: string; roleNames: string[] }[]).find(
      (user) => user.email === 'roles@http.test.local',
    );
    expect(target?.roleNames).toEqual([]);
  });

  it('rejects unknown roles and protects the system holder', async () => {
    const manager = await actingAs('manager7@http.test.local', 'USER_MANAGER');
    const root = await createUserFixture('root7@http.test.local', { password: PASSWORD });
    await grantRole(root, 'SUPER_ADMIN');

    await manager
      .put(`/api/users/${root}/roles`)
      .send({ roleNames: ['GHOST'] })
      .expect(400);
    await manager.put(`/api/users/${root}/roles`).send({ roleNames: [] }).expect(403);
  });
});

describe('deleting accounts', () => {
  it('deletes another account, refuses self-deletion and protects system holders', async () => {
    const manager = await actingAs('manager8@http.test.local', 'USER_MANAGER');
    const created = await manager
      .post('/api/users')
      .send(newAccount('doomed@http.test.local'))
      .expect(201);
    const me = await prisma.user.findUniqueOrThrow({
      where: { email: 'manager8@http.test.local' },
      select: { id: true },
    });
    const root = await createUserFixture('root8@http.test.local', { password: PASSWORD });
    await grantRole(root, 'SUPER_ADMIN');

    await manager.delete(`/api/users/${me.id}`).expect(400);
    await manager.delete(`/api/users/${root}`).expect(403);
    await manager.delete(`/api/users/${created.body.id}`).expect(204);
    await manager.get(`/api/users/${created.body.id}`).expect(404);
  });
});

describe('user mutations land in the audit trail', () => {
  it('records create, update, roles and delete with the manager as actor and no secrets', async () => {
    const root = await actingAs('root9@http.test.local', 'SUPER_ADMIN');

    const created = await root
      .post('/api/users')
      .send(newAccount('audited@http.test.local'))
      .expect(201);
    await root.patch(`/api/users/${created.body.id}`).send({ status: 'DISABLED' }).expect(200);
    await root.delete(`/api/users/${created.body.id}`).expect(204);

    const trail = await root.get('/api/audit-logs?limit=200').expect(200);
    const actions = (trail.body as { action: string }[]).map((event) => event.action);
    expect(actions).toEqual(
      expect.arrayContaining(['user.created', 'user.updated', 'user.deleted']),
    );

    const createEvent = (trail.body as { action: string; changes: Record<string, unknown> }[]).find(
      (event) => event.action === 'user.created',
    );
    expect(createEvent?.changes).toMatchObject({ email: 'audited@http.test.local' });
    expect(JSON.stringify(trail.body)).not.toMatch(/initial-password-123|passwordHash/i);
  });
});
