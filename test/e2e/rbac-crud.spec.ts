import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import { seedUser } from '../utils/seed-user.js';
import { createTestApp, type TestContext } from '../utils/create-test-app.js';

let ctx: TestContext;
let bearer: string;
let memberId: string;

async function login(): Promise<string> {
  const res = await request(ctx.app.getHttpServer())
    .post('/api/auth/login')
    .send({ email: 'rbac@test.local', password: 'rbac-password-123' })
    .expect(200);
  return res.body.accessToken as string;
}

function http(): request.Agent {
  return request(ctx.app.getHttpServer());
}

type AuthedRequests = Record<
  'get' | 'post' | 'patch' | 'put' | 'delete',
  (path: string) => request.Test
>;

function authed(): AuthedRequests {
  const header = (): string => `Bearer ${bearer}`;
  return {
    get: (path) => request(ctx.app.getHttpServer()).get(path).set('Authorization', header()),
    post: (path) => request(ctx.app.getHttpServer()).post(path).set('Authorization', header()),
    patch: (path) => request(ctx.app.getHttpServer()).patch(path).set('Authorization', header()),
    put: (path) => request(ctx.app.getHttpServer()).put(path).set('Authorization', header()),
    delete: (path) => request(ctx.app.getHttpServer()).delete(path).set('Authorization', header()),
  };
}

beforeAll(async () => {
  ctx = await createTestApp();
});

beforeEach(async () => {
  await resetTestDatabase();
  memberId = await seedUser('rbac@test.local', 'rbac-password-123');
  bearer = await login();
});

afterAll(async () => {
  await ctx.app.close();
});

describe('authentication on the RBAC surface', () => {
  it('rejects every role and permission route without a token', async () => {
    const requests: readonly (() => request.Test)[] = [
      () => http().get('/api/roles'),
      () => http().post('/api/roles').send({ name: 'NoToken', permissionKeys: [] }),
      () => http().get('/api/roles/any-id'),
      () => http().patch('/api/roles/any-id').send({ name: 'NoToken2' }),
      () => http().put('/api/roles/any-id/permissions').send({ permissionKeys: [] }),
      () => http().delete('/api/roles/any-id'),
      () => http().get('/api/permissions'),
      () => http().post('/api/permissions').send({ resource: 'docs', action: 'read', name: 'x' }),
      () => http().patch('/api/permissions/any-id').send({ name: 'x' }),
      () => http().delete('/api/permissions/any-id'),
    ];

    for (const run of requests) {
      await run().expect(401);
    }
  });

  it('rejects a tampered token', async () => {
    await request(ctx.app.getHttpServer())
      .get('/api/roles')
      .set('Authorization', 'Bearer not.a.jwt')
      .expect(401);
  });
});

describe('roles over HTTP', () => {
  it('creates, reads, updates and deletes a role with its grants', async () => {
    const permission = await prisma.permission.create({
      data: { key: 'docs.read', name: 'Read docs', resource: 'docs', action: 'read' },
    });

    const created = await authed()
      .post('/api/roles')
      .send({ name: 'Editor', description: 'Document editors', permissionKeys: [permission.key] })
      .expect(201);

    expect(created.body).toMatchObject({
      id: expect.any(String),
      name: 'Editor',
      isSystem: false,
      permissionKeys: [permission.key],
    });
    expect(created.body.passwordHash).toBeUndefined();

    const listed = await authed().get('/api/roles').expect(200);
    const roleViews: { name: string }[] = listed.body;
    expect(roleViews.map((role) => role.name)).toContain('Editor');

    const fetched = await authed().get(`/api/roles/${created.body.id}`).expect(200);
    expect(fetched.body.id).toBe(created.body.id);

    const updated = await authed()
      .patch(`/api/roles/${created.body.id}`)
      .send({ name: 'Senior-Editor' })
      .expect(200);
    expect(updated.body.name).toBe('Senior-Editor');

    await authed()
      .put(`/api/roles/${created.body.id}/permissions`)
      .send({ permissionKeys: [] })
      .expect(200);
    const emptied = await authed().get(`/api/roles/${created.body.id}`).expect(200);
    expect(emptied.body.permissionKeys).toEqual([]);

    await authed().delete(`/api/roles/${created.body.id}`).expect(204);
    await authed().get(`/api/roles/${created.body.id}`).expect(404);
  });

  it('answers a duplicate role name with 409', async () => {
    await authed().post('/api/roles').send({ name: 'Editor', permissionKeys: [] }).expect(201);
    await authed().post('/api/roles').send({ name: 'Editor', permissionKeys: [] }).expect(409);
  });

  it('answers malformed bodies with 400', async () => {
    await authed().post('/api/roles').send({ name: '' }).expect(400);
    await authed()
      .post('/api/roles')
      .send({ name: 'Ok', permissionKeys: ['not-a-key'] })
      .expect(400);
  });

  it('protects the system role from modification and deletion', async () => {
    const system = await prisma.role.create({
      data: { name: 'SUPER_ADMIN', isSystem: true },
    });

    await authed().patch(`/api/roles/${system.id}`).send({ name: 'Hollow' }).expect(403);
    await authed()
      .put(`/api/roles/${system.id}/permissions`)
      .send({ permissionKeys: [] })
      .expect(403);
    await authed().delete(`/api/roles/${system.id}`).expect(403);

    const untouched = await prisma.role.findUnique({ where: { id: system.id } });
    expect(untouched?.name).toBe('SUPER_ADMIN');
    expect(untouched?.isSystem).toBe(true);
  });

  it('refuses to delete a role that still has members with 409', async () => {
    const created = await authed().post('/api/roles').send({ name: 'Staff' }).expect(201);
    await prisma.userRole.create({
      data: { userId: memberId, roleId: created.body.id as string },
    });
    await authed().delete(`/api/roles/${created.body.id}`).expect(409);
  });

  it('never exposes raw rows: unknown ids give a 404, not a 500', async () => {
    await authed().get('/api/roles/cuid-not-here').expect(404);
    await authed().patch('/api/roles/cuid-not-here').send({ name: 'Renamed' }).expect(404);
    await authed().delete('/api/roles/cuid-not-here').expect(404);
  });
});

describe('permissions over HTTP', () => {
  it('creates, lists, updates and deletes a permission', async () => {
    const created = await authed()
      .post('/api/permissions')
      .send({ resource: 'invoices', action: 'settle', name: 'Settle invoices' })
      .expect(201);

    expect(created.body.key).toBe('invoices.settle');

    const listed = await authed().get('/api/permissions').expect(200);
    const permissionViews: { key: string }[] = listed.body;
    expect(permissionViews.map((item) => item.key)).toContain('invoices.settle');

    const updated = await authed()
      .patch(`/api/permissions/${created.body.id}`)
      .send({ name: 'Finalize invoices' })
      .expect(200);
    expect(updated.body).toMatchObject({ name: 'Finalize invoices', key: 'invoices.settle' });

    await authed().delete(`/api/permissions/${created.body.id}`).expect(204);
  });

  it('rejects an invalid resource or action slug with 400', async () => {
    await authed()
      .post('/api/permissions')
      .send({ resource: 'In voices', action: 'settle', name: 'Nope' })
      .expect(400);
    await authed()
      .post('/api/permissions')
      .send({ resource: 'invoices', action: 'settle', name: '' })
      .expect(400);
  });

  it('refuses to create the same key twice with 409', async () => {
    await authed()
      .post('/api/permissions')
      .send({ resource: 'invoices', action: 'settle', name: 'Settle' })
      .expect(201);
    await authed()
      .post('/api/permissions')
      .send({ resource: 'invoices', action: 'settle', name: 'Settle again' })
      .expect(409);
  });

  it('refuses to delete a permission that a role still grants with 409', async () => {
    const created = await authed()
      .post('/api/permissions')
      .send({ resource: 'invoices', action: 'settle', name: 'Settle' })
      .expect(201);
    const role = await authed().post('/api/roles').send({ name: 'Billing' }).expect(201);

    await authed()
      .put(`/api/roles/${role.body.id}/permissions`)
      .send({ permissionKeys: [created.body.key] })
      .expect(200);

    await authed().delete(`/api/permissions/${created.body.id}`).expect(409);
  });
});
