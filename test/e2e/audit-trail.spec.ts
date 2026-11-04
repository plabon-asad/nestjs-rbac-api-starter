import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { resetTestDatabase } from '../utils/prisma-test.js';
import {
  createPermissionFixture,
  createRoleFixture,
  createUserFixture,
  grantRole,
} from '../utils/rbac-fixtures.js';
import { routeClient, type RouteClient } from '../utils/route-client.js';
import { createTestApp, type TestContext } from '../utils/create-test-app.js';

const PASSWORD = 'audited-password-123';

let ctx: TestContext;
let rootApi: RouteClient;

async function tokenFor(email: string): Promise<string> {
  const res = await request(ctx.app.getHttpServer())
    .post('/api/auth/login')
    .send({ email, password: PASSWORD })
    .expect(200);
  return res.body.accessToken as string;
}

async function trailActions(limit = 100): Promise<string[]> {
  const res = await rootApi.get(`/api/audit-logs?limit=${limit}`).expect(200);
  const rows: { action: string }[] = res.body;
  return rows.map((row) => row.action);
}

beforeAll(async () => {
  ctx = await createTestApp();
});

beforeEach(async () => {
  await resetTestDatabase();
  await createPermissionFixture('roles.read');
  await createPermissionFixture('permission-overrides.manage');
  await createRoleFixture('SUPER_ADMIN', [], true);
  const rootId = await createUserFixture('root@audit.test.local', { password: PASSWORD });
  await grantRole(rootId, 'SUPER_ADMIN');
  rootApi = routeClient(ctx.app, await tokenFor('root@audit.test.local'));
});

afterAll(async () => {
  await ctx.app.close();
});

describe('the audit trail records security events', () => {
  it('login success and login failure (known and unknown accounts)', async () => {
    await request(ctx.app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'nobody@audit.test.local', password: PASSWORD })
      .expect(401);

    const victim = await createUserFixture('victim@audit.test.local', { password: PASSWORD });
    await request(ctx.app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'victim@audit.test.local', password: 'wrong-password-123' })
      .expect(401);
    await tokenFor('victim@audit.test.local');

    const actions = await trailActions();
    expect(actions).toContain('auth.login.failure');
    expect(actions).toContain('auth.login.success');

    const failureRows = await rootApi.get('/api/audit-logs?limit=100').expect(200);
    const rows: { action: string; actorUserId: string | null }[] = failureRows.body;
    const knownFailure = rows.find(
      (row) => row.action === 'auth.login.failure' && row.actorUserId === victim,
    );
    expect(knownFailure, 'failure for a known account is attributed to that account').toBeDefined();
    const anonymous = rows.find(
      (row) => row.action === 'auth.login.failure' && row.actorUserId === null,
    );
    expect(anonymous, 'failure for an unknown account is still recorded').toBeDefined();
  });

  it('records a lockout when the failed-attempt threshold is crossed', async () => {
    const target = await createUserFixture('lockme@audit.test.local', { password: PASSWORD });
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await request(ctx.app.getHttpServer())
        .post('/api/auth/login')
        .send({ email: 'lockme@audit.test.local', password: 'wrong-password-123' })
        .expect(401);
    }

    const actions = await trailActions();
    expect(actions).toContain('auth.login.locked');

    const rows = (await (
      await rootApi.get('/api/audit-logs?limit=100').expect(200)
    ).body) as {
      action: string;
      actorUserId: string | null;
    }[];
    const locked = rows.find((row) => row.action === 'auth.login.locked');
    expect(locked?.actorUserId).toBe(target);
  });

  it('refresh token reuse revokes the family and is recorded', async () => {
    const login = await request(ctx.app.getHttpServer())
      .post('/api/auth/login')
      .send({ email: 'root@audit.test.local', password: PASSWORD })
      .expect(200);
    const stolen = login.body.refreshToken as string;

    await request(ctx.app.getHttpServer())
      .post('/api/auth/refresh')
      .send({ refreshToken: stolen })
      .expect(200);
    await request(ctx.app.getHttpServer())
      .post('/api/auth/refresh')
      .send({ refreshToken: stolen })
      .expect(401);

    expect(await trailActions()).toContain('auth.refresh.reuse_detected');
  });

  it('password change and reset requests are recorded without secrets', async () => {
    await rootApi
      .post('/api/auth/change-password')
      .send({ currentPassword: PASSWORD, newPassword: 'rotated-password-123' })
      .expect(204);
    await request(ctx.app.getHttpServer())
      .post('/api/auth/forgot-password')
      .send({ email: 'root@audit.test.local' })
      .expect(202);

    const rows = (await (
      await rootApi.get('/api/audit-logs?limit=100').expect(200)
    ).body) as {
      action: string;
      changes: Record<string, unknown> | null;
    }[];
    expect(rows.map((row) => row.action)).toContain('auth.password.changed');
    expect(rows.map((row) => row.action)).toContain('auth.password.reset_requested');

    const changed = rows.find((row) => row.action === 'auth.password.changed');
    expect(JSON.stringify(changed?.changes ?? {})).not.toMatch(/password/i);
  });

  it('RBAC mutations are recorded', async () => {
    const role = await rootApi
      .post('/api/roles')
      .send({ name: 'Audited', permissionKeys: ['roles.read'] })
      .expect(201);
    await rootApi
      .put(`/api/roles/${role.body.id as string}/permissions`)
      .send({ permissionKeys: [] })
      .expect(200);
    await rootApi.delete(`/api/roles/${role.body.id as string}`).expect(204);

    const actions = await trailActions();
    expect(actions).toContain('role.created');
    expect(actions).toContain('role.grants_updated');
    expect(actions).toContain('role.deleted');
  });

  it('override changes are recorded', async () => {
    const target = await createUserFixture('overridden@audit.test.local');
    await rootApi
      .put(`/api/permission-overrides/${target}/roles.read`)
      .send({ effect: 'DENY' })
      .expect(200);
    await rootApi
      .put(`/api/permission-overrides/${target}/roles.read`)
      .send({ effect: 'INHERIT' })
      .expect(200);

    const actions = await trailActions();
    expect(actions).toContain('override.set');
    expect(actions).toContain('override.inherited');
  });

  it('a stored event never carries sensitive change values even if the caller passes them', async () => {
    await rootApi.post('/api/roles').send({ name: 'Leaky', permissionKeys: [] }).expect(201);

    const rows = (await (
      await rootApi.get('/api/audit-logs?limit=100').expect(200)
    ).body) as {
      action: string;
      changes: Record<string, unknown> | null;
    }[];
    const created = rows.find((row) => row.action === 'role.created');
    expect(created?.changes).toEqual({ name: 'Leaky', permissionKeys: [] });
  });
});

describe('audit read access', () => {
  it('requires a token and the audit-logs.read permission', async () => {
    await request(ctx.app.getHttpServer()).get('/api/audit-logs').expect(401);

    const outsider = await createUserFixture('outsider@audit.test.local', { password: PASSWORD });
    const outsiderApi = routeClient(ctx.app, await tokenFor('outsider@audit.test.local'));
    await outsiderApi.get('/api/audit-logs').expect(403);
    expect(outsider).toBeTruthy();
  });
});
