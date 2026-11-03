import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import request from 'supertest';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import { seedUser } from '../utils/seed-user.js';
import { createTestApp, type TestContext } from '../utils/create-test-app.js';

const INVALID_CREDENTIALS_MESSAGE = 'Invalid email or password.';

let ctx: TestContext;
let http: () => request.Agent;

function login(email: string, password: string): request.Test {
  return request(ctx.app.getHttpServer()).post('/api/auth/login').send({ email, password });
}

beforeAll(async () => {
  ctx = await createTestApp();
  http = () => request(ctx.app.getHttpServer());
});

afterAll(async () => {
  await ctx.app.close();
});

beforeEach(async () => {
  await resetTestDatabase();
});

describe('POST /auth/login', () => {
  it('returns a token pair and user profile on valid credentials', async () => {
    await seedUser('alice@test.local', 'wonderland-12345');
    const res = await login('alice@test.local', 'wonderland-12345').expect(200);

    expect(res.body.accessToken).toEqual(expect.any(String));
    expect(res.body.refreshToken).toEqual(expect.any(String));
    expect(res.body.user).toMatchObject({ email: 'alice@test.local' });
    expect(res.body.user.passwordHash).toBeUndefined();

    const setCookie = res.headers['set-cookie']?.[0] ?? '';
    expect(setCookie).toMatch(/refresh_token=/);
    expect(setCookie).toMatch(/HttpOnly/i);
  });

  it('answers unknown email and wrong password with one identical 401 (no enumeration)', async () => {
    await seedUser('bob@test.local', 'builder-123456');
    const wrongPassword = await login('bob@test.local', 'nope-nope-nope');
    const unknownEmail = await login('nobody@test.local', 'whatever-123456');

    expect(wrongPassword.status).toBe(401);
    expect(unknownEmail.status).toBe(401);
    expect(wrongPassword.body.message).toBe(INVALID_CREDENTIALS_MESSAGE);
    expect(unknownEmail.body.message).toBe(INVALID_CREDENTIALS_MESSAGE);
  });

  it('refuses disabled users with the same 401 and without touching counters', async () => {
    const id = await seedUser('carol@test.local', 'singing-123456', { status: 'DISABLED' });
    const res = await login('carol@test.local', 'singing-123456').expect(401);
    expect(res.body.message).toBe(INVALID_CREDENTIALS_MESSAGE);

    const user = await prisma.user.findUnique({ where: { id } });
    expect(user?.failedLoginCount).toBe(0);
  });

  it('normalizes email case before lookup', async () => {
    await seedUser('dave@test.local', 'pipers-1234567');
    await login('DAVE@Test.Local', 'pipers-1234567').expect(200);
  });

  it('rejects malformed bodies with 400', async () => {
    await http().post('/api/auth/login').send({ email: 'not-an-email' }).expect(400);
    await http().post('/api/auth/login').send({ email: 'a@b.co', password: '' }).expect(400);
  });
});

describe('account lockout', () => {
  it('locks after 5 consecutive failures and blocks even the correct password', async () => {
    const id = await seedUser('eve@test.local', 'turtle-1234567');

    for (let attempt = 0; attempt < 5; attempt += 1) {
      await login('eve@test.local', 'wrong-attempt-1').expect(401);
    }

    const locked = await prisma.user.findUnique({ where: { id } });
    expect(locked?.failedLoginCount).toBe(5);
    expect(locked?.lockedUntil?.getTime()).toBeGreaterThan(Date.now());

    await login('eve@test.local', 'turtle-1234567').expect(401);
  });

  it('clears counters after a successful login following lockout expiry', async () => {
    const id = await seedUser('frank@test.local', 'clocks-1234567');
    for (let attempt = 0; attempt < 5; attempt += 1) {
      await login('frank@test.local', 'wrong-attempt-1').expect(401);
    }
    await prisma.user.update({
      where: { id },
      data: { lockedUntil: new Date(Date.now() - 1000) },
    });

    await login('frank@test.local', 'clocks-1234567').expect(200);
    const user = await prisma.user.findUnique({ where: { id } });
    expect(user?.failedLoginCount).toBe(0);
    expect(user?.lockedUntil).toBeNull();
  });

  it('resets the failure counter on a successful login', async () => {
    const id = await seedUser('Grace@test.local', 'hopper-123456');
    await login('Grace@test.local', 'wrong-attempt-1').expect(401);
    await login('grace@test.local', 'hopper-123456').expect(200);

    const user = await prisma.user.findUnique({ where: { id } });
    expect(user?.failedLoginCount).toBe(0);
  });
});

describe('GET /auth/me', () => {
  it('returns 401 without a token, with a garbage token, or after revocation of status', async () => {
    await http().get('/api/auth/me').expect(401);
    await http().get('/api/auth/me').set('Authorization', 'Bearer garbage.token.here').expect(401);
  });

  it('returns the current user view without secrets', async () => {
    await seedUser('heidi@test.local', 'alpiner-12345');
    const { body } = await login('heidi@test.local', 'alpiner-12345');
    const me = await http().get('/api/auth/me').set('Authorization', `Bearer ${body.accessToken}`);

    expect(me.status).toBe(200);
    expect(me.body.email).toBe('heidi@test.local');
    expect(me.body.passwordHash).toBeUndefined();
  });

  it('rejects tokens issued for a disabled user immediately (per-request status check)', async () => {
    const id = await seedUser('ivan@test.local', 'koloskov-1234');
    const { body } = await login('ivan@test.local', 'koloskov-1234');

    await prisma.user.update({ where: { id }, data: { status: 'DISABLED' } });

    await http().get('/api/auth/me').set('Authorization', `Bearer ${body.accessToken}`).expect(403);
  });
});

describe('POST /auth/refresh', () => {
  it('rotates the refresh token and returns a fresh access token', async () => {
    await seedUser('judy@test.local', 'samaritan-1234');
    const { body } = await login('judy@test.local', 'samaritan-1234');

    const refreshed = await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: body.refreshToken })
      .expect(200);

    expect(refreshed.body.refreshToken).not.toBe(body.refreshToken);
    expect(refreshed.body.accessToken).toEqual(expect.any(String));
  });

  it('revokes the entire family when a rotated token is replayed', async () => {
    await seedUser('karl@test.local', 'rogaine-12345');
    const { body } = await login('karl@test.local', 'rogaine-12345');

    const rotated = await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: body.refreshToken })
      .expect(200);

    await http().post('/api/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);

    // The legitimately rotated token must now be dead too (family burn).
    await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: rotated.body.refreshToken })
      .expect(401);
  });

  it('accepts the httpOnly cookie when no body token is provided', async () => {
    await seedUser('lena@test.local', 'testuser-12345');
    const loginRes = await login('lena@test.local', 'testuser-12345');
    const cookie = loginRes.headers['set-cookie']?.[0]?.split(';')[0];

    const refreshed = await http()
      .post('/api/auth/refresh')
      .set('Cookie', cookie!)
      .send({})
      .expect(200);
    expect(refreshed.body.accessToken).toEqual(expect.any(String));
  });

  it('rejects unknown/garbage tokens with 401', async () => {
    await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: 'x'.repeat(60) })
      .expect(401);
  });
});

describe('logout', () => {
  it('revokes only the presented session on logout; access token drains naturally', async () => {
    await seedUser('mallory@test.local', 'malicious-1234');
    const first = await login('mallory@test.local', 'malicious-1234');
    const second = await login('mallory@test.local', 'malicious-1234');

    await http()
      .post('/api/auth/logout')
      .send({ refreshToken: first.body.refreshToken })
      .expect(204);

    await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: first.body.refreshToken })
      .expect(401);
    await http()
      .post('/api/auth/refresh')
      .send({ refreshToken: second.body.refreshToken })
      .expect(200);
  });

  it('logout-all revokes every session for the user', async () => {
    await seedUser('nina@test.local', 'trustworthy-12');
    const a = await login('nina@test.local', 'trustworthy-12');
    const b = await login('nina@test.local', 'trustworthy-12');

    await http().post('/api/auth/logout-all').set('Authorization', `Bearer ${a.body.accessToken}`);

    await http().post('/api/auth/refresh').send({ refreshToken: a.body.refreshToken }).expect(401);
    await http().post('/api/auth/refresh').send({ refreshToken: b.body.refreshToken }).expect(401);
  });

  it('requires authentication for logout-all', async () => {
    await http().post('/api/auth/logout-all').expect(401);
  });
});

describe('forgot / reset password', () => {
  it('returns the same status for unknown emails and never reveals existence', async () => {
    const res = await http().post('/api/auth/forgot-password').send({ email: 'ghost@test.local' });
    expect(res.status).toBe(202);
    expect(ctx.mailer.sent).toHaveLength(0);
  });

  it('delivers a reset token for a known email and resets the password once', async () => {
    const id = await seedUser('oscar@test.local', 'old-password-123');
    await http().post('/api/auth/forgot-password').send({ email: 'oscar@test.local' });

    expect(ctx.mailer.sent).toHaveLength(1);
    const token = ctx.mailer.sent[0]!.token;

    await http()
      .post('/api/auth/reset-password')
      .send({ token, newPassword: 'brand-new-password' })
      .expect([200, 204]);

    // passwordChangedAt recorded, old sessions revoked.
    const user = await prisma.user.findUnique({ where: { id } });
    expect(user?.passwordChangedAt.getTime()).toBeGreaterThan(0);
    const activeAfterReset = await prisma.refreshToken.count({
      where: { userId: id, revokedAt: null },
    });
    expect(activeAfterReset).toBe(0);

    await login('oscar@test.local', 'brand-new-password').expect(200);
    await login('oscar@test.local', 'old-password-123').expect(401);

    // Token is single-use.
    await http()
      .post('/api/auth/reset-password')
      .send({ token, newPassword: 'another-password-1' })
      .expect(400);
  });

  it('rejects invalid or expired reset tokens with 400', async () => {
    const id = await seedUser('peggy@test.local', 'petruchio-123');
    await http().post('/api/auth/forgot-password').send({ email: 'peggy@test.local' });
    const token = ctx.mailer.sent[0]!.token;

    await http()
      .post('/api/auth/reset-password')
      .send({ token: 'totally-made-up-token', newPassword: 'whatever-123456' })
      .expect(400);

    const resetRow = await prisma.passwordResetToken.findFirst({ where: { userId: id } });
    expect(resetRow).not.toBeNull();
    await prisma.passwordResetToken.update({
      where: { id: resetRow!.id },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    await http()
      .post('/api/auth/reset-password')
      .send({ token, newPassword: 'whatever-123456' })
      .expect(400);
  });

  it('rejects weak new passwords with 400', async () => {
    await http()
      .post('/api/auth/reset-password')
      .send({ token: 'x'.repeat(40), newPassword: 'short' })
      .expect(400);
  });
});

describe('POST /auth/change-password', () => {
  it('requires the correct current password and revokes all sessions on success', async () => {
    await seedUser('rosa@test.local', 'garden-123456');
    const { body } = await login('rosa@test.local', 'garden-123456');
    const auth = (req: request.Test) => req.set('Authorization', `Bearer ${body.accessToken}`);

    await auth(
      http()
        .post('/api/auth/change-password')
        .send({ currentPassword: 'nope', newPassword: 'fresh-password' }),
    ).expect(401);
    await auth(
      http()
        .post('/api/auth/change-password')
        .send({ currentPassword: 'garden-123456', newPassword: 'fresh-password' }),
    ).expect([200, 204]);

    await login('rosa@test.local', 'fresh-password').expect(200);
    await http().post('/api/auth/refresh').send({ refreshToken: body.refreshToken }).expect(401);
  });

  it('requires authentication', async () => {
    await http()
      .post('/api/auth/change-password')
      .send({ currentPassword: 'a-123456789', newPassword: 'b-123456789' })
      .expect(401);
  });
});
