import { beforeAll, afterEach, describe, expect, it } from 'vitest';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { RefreshTokenService } from '../../src/modules/auth/services/refresh-token.service.js';
import { prisma, resetTestDatabase, testEnv } from '../utils/prisma-test.js';

let service: RefreshTokenService;
let userId: string;

async function createUser(email: string): Promise<string> {
  const passwords = new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash: await passwords.hash('test-password-1234'),
      firstName: 'Test',
      lastName: 'User',
    },
  });
  return user.id;
}

beforeAll(async () => {
  await resetTestDatabase();
  service = new RefreshTokenService(prisma, testEnv);
  userId = await createUser('refresh-owner@test.local');
});

afterEach(async () => {
  await prisma.refreshToken.deleteMany({ where: { userId } });
});

describe('RefreshTokenService', () => {
  it('stores only a hash of the refresh token, never the plaintext', async () => {
    const issued = await service.issue(userId, { ip: '127.0.0.1', userAgent: 'vitest' });
    expect(issued.token.length).toBeGreaterThanOrEqual(43);

    const rows = await prisma.refreshToken.findMany({ where: { userId } });
    expect(rows).toHaveLength(1);
    expect(rows[0]!.tokenHash).not.toContain(issued.token);
    expect(rows[0]!.tokenHash).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rotates a valid token: old one revoked, new one in same family', async () => {
    const first = await service.issue(userId, { ip: '127.0.0.1', userAgent: 'vitest' });
    const second = await service.rotate(first.token, { ip: '127.0.0.1', userAgent: 'vitest' });

    expect(second.token).not.toBe(first.token);
    expect(second.familyId).toBe(first.familyId);

    const oldRow = await prisma.refreshToken.findUnique({ where: { tokenHash: first.tokenHash } });
    expect(oldRow?.revokedAt).not.toBeNull();
  });

  it('revokes the whole family when a rotated token is reused', async () => {
    const first = await service.issue(userId, { ip: '127.0.0.1', userAgent: 'vitest' });
    const second = await service.rotate(first.token, { ip: '127.0.0.1', userAgent: 'vitest' });
    await service.rotate(second.token, { ip: '127.0.0.1', userAgent: 'vitest' });

    // Replay of the already-rotated `first` token must fail and nuke the family.
    await expect(
      service.rotate(first.token, { ip: '127.0.0.1', userAgent: 'attacker' }),
    ).rejects.toThrow(/reuse/i);

    const rows = await prisma.refreshToken.findMany({ where: { familyId: first.familyId } });
    expect(rows.length).toBeGreaterThan(1);
    expect(rows.every((row) => row.revokedAt !== null)).toBe(true);
  });

  it('rejects an unknown token', async () => {
    await expect(
      service.rotate('definitely-not-a-real-token', { ip: '127.0.0.1', userAgent: 'x' }),
    ).rejects.toThrow();
  });

  it('rejects an expired token without rotating', async () => {
    const issued = await service.issue(userId, { ip: '127.0.0.1', userAgent: 'x' });
    await prisma.refreshToken.update({
      where: { tokenHash: issued.tokenHash },
      data: { expiresAt: new Date(Date.now() - 1000) },
    });
    await expect(
      service.rotate(issued.token, { ip: '127.0.0.1', userAgent: 'x' }),
    ).rejects.toThrow();
  });

  it('revokes a single token on logout', async () => {
    const a = await service.issue(userId, { ip: '127.0.0.1', userAgent: 'x' });
    const b = await service.issue(userId, { ip: '127.0.0.1', userAgent: 'x' });
    await service.revoke(a.token);

    expect(
      (await prisma.refreshToken.findUnique({ where: { tokenHash: a.tokenHash } }))?.revokedAt,
    ).not.toBeNull();
    expect(
      (await prisma.refreshToken.findUnique({ where: { tokenHash: b.tokenHash } }))?.revokedAt,
    ).toBeNull();
  });

  it('revokes every active token for a user on logout-all', async () => {
    await service.issue(userId, { ip: '127.0.0.1', userAgent: 'x' });
    await service.issue(userId, { ip: '127.0.0.1', userAgent: 'x' });
    await service.revokeAllForUser(userId);

    const active = await prisma.refreshToken.findMany({
      where: { userId, revokedAt: null },
    });
    expect(active).toHaveLength(0);
  });

  it('does not revoke a family member that was already revoked (idempotent reuse check)', async () => {
    const first = await service.issue(userId, { ip: '127.0.0.1', userAgent: 'x' });
    await service.rotate(first.token, { ip: '127.0.0.1', userAgent: 'x' });
    await expect(service.rotate(first.token, { ip: '127.0.0.1', userAgent: 'x' })).rejects.toThrow(
      /reuse/i,
    );
    // Second replay of the same stale token: still rejected, no new state to break.
    await expect(service.rotate(first.token, { ip: '127.0.0.1', userAgent: 'x' })).rejects.toThrow(
      /reuse/i,
    );
  });
});
