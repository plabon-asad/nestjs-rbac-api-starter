import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { seedRbac } from '../../src/database/seeds/seed-rbac.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import { routeClient, type RouteClient } from '../utils/route-client.js';
import { createTestApp, type TestContext } from '../utils/create-test-app.js';

const ROOT_EMAIL = 'root@lifecycle.test.local';
const ROOT_PASSWORD = 'root-lifecycle-password-123';
const ALICE_INITIAL = 'alice-initial-password-123';
const BOB_INITIAL = 'bob-initial-password-123';
const lowCostPasswords = new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });

let ctx: TestContext;

async function tokenFor(email: string, password: string): Promise<string> {
  const res = await request(ctx.app.getHttpServer())
    .post('/api/auth/login')
    .send({ email, password })
    .expect(200);
  return res.body.accessToken as string;
}

async function loginFailure(email: string, password: string): Promise<number> {
  return (await request(ctx.app.getHttpServer()).post('/api/auth/login').send({ email, password }))
    .status;
}

beforeAll(async () => {
  ctx = await createTestApp();
});

beforeEach(async () => {
  await resetTestDatabase();
  await seedRbac(prisma, {
    superAdmin: { email: ROOT_EMAIL, password: ROOT_PASSWORD },
    passwords: lowCostPasswords,
  });
});

afterAll(async () => {
  await ctx.app.close();
});

describe('full lifecycle: bootstrap -> staff -> alice escalation-free journey -> removal', () => {
  it('walks one account from seeded bootstrap to deleted, with every control biting in order', async () => {
    const http = () => request(ctx.app.getHttpServer());

    // 1. Seeding is idempotent and never overwrites the bootstrap password.
    const secondRun = await seedRbac(prisma, {
      superAdmin: { email: ROOT_EMAIL, password: 'rotated-bootstrap-password' },
      passwords: lowCostPasswords,
    });
    expect(secondRun.superAdminCreated).toBe(false);
    expect(secondRun.superAdminPasswordPreserved).toBe(true);
    await tokenFor(ROOT_EMAIL, ROOT_PASSWORD);

    // 2. The root sees the full catalogue.
    const rootApi: RouteClient = routeClient(ctx.app, await tokenFor(ROOT_EMAIL, ROOT_PASSWORD));
    const catalogue = await rootApi.get('/api/permissions').expect(200);
    const catalogueKeys = (catalogue.body as { key: string }[]).map((p) => p.key);
    for (const key of ['users.read', 'users.create', 'roles.read', 'audit-logs.read']) {
      expect(catalogueKeys).toContain(key);
    }

    // 3. Root defines a staff role and two accounts.
    await rootApi
      .post('/api/roles')
      .send({ name: 'STAFF', permissionKeys: ['users.read', 'users.update', 'roles.read'] })
      .expect(201);
    const alice = await rootApi
      .post('/api/users')
      .send({
        email: 'alice@lifecycle.test.local',
        password: ALICE_INITIAL,
        firstName: 'Alice',
        lastName: 'Anderson',
        roleNames: ['READ_ONLY'],
      })
      .expect(201);
    await rootApi
      .post('/api/users')
      .send({
        email: 'bob@lifecycle.test.local',
        password: BOB_INITIAL,
        firstName: 'Bob',
        lastName: 'Baxter',
        roleNames: [],
      })
      .expect(201);

    // 4. Alice starts read-only: she can look but never write.
    let aliceApi = routeClient(
      ctx.app,
      await tokenFor('alice@lifecycle.test.local', ALICE_INITIAL),
    );
    await aliceApi.get('/api/roles').expect(200);
    await aliceApi
      .post('/api/roles')
      .send({ name: 'SELF_PROMOTION', permissionKeys: [] })
      .expect(403);

    // 5. Root promotes her to STAFF: the new write right bites on the very next request.
    const bob = await prisma.user.findUniqueOrThrow({
      where: { email: 'bob@lifecycle.test.local' },
      select: { id: true },
    });
    await rootApi
      .put(`/api/users/${alice.body.id}/roles`)
      .send({ roleNames: ['STAFF'] })
      .expect(200);
    await aliceApi.patch(`/api/users/${bob.id}`).send({ firstName: 'Bobby' }).expect(200);

    // 6. A DENY override strips that right instantly; INHERIT restores it.
    await rootApi
      .put(`/api/permission-overrides/${alice.body.id}/users.update`)
      .send({ effect: 'DENY' })
      .expect(200);
    await aliceApi.patch(`/api/users/${bob.id}`).send({ firstName: 'Bob' }).expect(403);
    await rootApi
      .put(`/api/permission-overrides/${alice.body.id}/users.update`)
      .send({ effect: 'INHERIT' })
      .expect(200);
    await aliceApi.patch(`/api/users/${bob.id}`).send({ firstName: 'Bobby' }).expect(200);

    // 7. Alice rotates her own password; the old one stops working.
    await aliceApi
      .post('/api/auth/change-password')
      .send({ currentPassword: ALICE_INITIAL, newPassword: 'alice-rotated-password-123' })
      .expect(204);
    expect(await loginFailure('alice@lifecycle.test.local', ALICE_INITIAL)).toBe(401);
    await tokenFor('alice@lifecycle.test.local', 'alice-rotated-password-123');

    // 8. Five bad logins lock the account, even with the now-correct password;
    //    an admin reactivation clears the lockout.
    for (let attempt = 0; attempt < 5; attempt += 1) {
      expect(
        await loginFailure('alice@lifecycle.test.local', 'wrong-password-wrong-password'),
      ).toBe(401);
    }
    expect(await loginFailure('alice@lifecycle.test.local', 'alice-rotated-password-123')).toBe(
      401,
    );
    await rootApi.patch(`/api/users/${alice.body.id}`).send({ status: 'ACTIVE' }).expect(200);
    await tokenFor('alice@lifecycle.test.local', 'alice-rotated-password-123');

    // 9. Refresh-token reuse revokes the family and is refused.
    const refreshPair = await http()
      .post('/api/auth/login')
      .send({ email: 'alice@lifecycle.test.local', password: 'alice-rotated-password-123' })
      .expect(200);
    await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: refreshPair.body.refreshToken })
      .expect(200);
    await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: refreshPair.body.refreshToken })
      .expect(401);

    // 10. Root disables Alice: her freshly issued access token dies on the next request.
    const freshToken = await tokenFor('alice@lifecycle.test.local', 'alice-rotated-password-123');
    aliceApi = routeClient(ctx.app, freshToken);
    await aliceApi.get('/api/roles').expect(200);
    await rootApi.patch(`/api/users/${alice.body.id}`).send({ status: 'DISABLED' }).expect(200);
    await aliceApi.get('/api/roles').expect(403);
    expect(await loginFailure('alice@lifecycle.test.local', 'alice-rotated-password-123')).toBe(
      401,
    );

    // 11. Bob resets through the mailer and is then deleted by root.
    await http()
      .post('/api/auth/forgot-password')
      .send({ email: 'bob@lifecycle.test.local' })
      .expect(202);
    const mail = ctx.mailer.sent[ctx.mailer.sent.length - 1];
    expect(mail?.to).toBe('bob@lifecycle.test.local');
    await http()
      .post('/api/auth/reset-password')
      .send({ token: mail?.token, newPassword: 'bob-reset-password-123' })
      .expect(204);
    expect(await loginFailure('bob@lifecycle.test.local', BOB_INITIAL)).toBe(401);
    await tokenFor('bob@lifecycle.test.local', 'bob-reset-password-123');

    await rootApi.delete(`/api/users/${bob.id}`).expect(204);
    await rootApi.get(`/api/users/${bob.id}`).expect(404);

    // 12. Every security-relevant step above is in the trail, without secret material.
    const trail = await rootApi.get('/api/audit-logs?limit=200').expect(200);
    const actions = new Set((trail.body as { action: string }[]).map((event) => event.action));
    for (const action of [
      'role.created',
      'user.created',
      'user.roles_assigned',
      'override.set',
      'override.inherited',
      'auth.password.changed',
      'auth.login.locked',
      'auth.refresh.reuse_detected',
      'auth.password.reset_requested',
      'auth.password.reset',
      'user.updated',
      'user.deleted',
    ]) {
      expect(actions, `audit trail must contain ${action}`).toContain(action);
    }
    expect(JSON.stringify(trail.body)).not.toMatch(
      /lifecycle-password|initial-password|rotated-password|reset-password-123|passwordHash/,
    );
  });
});
