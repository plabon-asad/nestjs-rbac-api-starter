import { describe, expect, it, vi } from 'vitest';
import { TokenService, type AccessClaims } from '../../src/modules/auth/services/token.service.js';
import { makeTestEnv } from '../utils/make-env.js';

function serviceWith(ttlSeconds: number): TokenService {
  return new TokenService(makeTestEnv({ accessToken: { ttlSeconds } }));
}

const user = { id: 'user_123' };

describe('TokenService — access tokens', () => {
  it('signs a JWT carrying only identity claims, never permissions', async () => {
    const service = serviceWith(900);
    const token = await service.signAccessToken(user.id, 'session_1');
    const claims = await service.verifyAccessToken(token);

    expect(claims.sub).toBe(user.id);
    expect(claims.sid).toBe('session_1');
    expect(claims.jti).toEqual(expect.any(String));
    expect(claims.exp).toBe(claims.iat + 900);
    const record = claims as unknown as Record<string, unknown>;
    expect(record['permissions']).toBeUndefined();
    expect(record['roles']).toBeUndefined();
  });

  it('validates issuer and audience from configuration', async () => {
    const service = serviceWith(900);
    const token = await service.signAccessToken(user.id, 'session_1');
    const claims = await service.verifyAccessToken(token);
    expect(claims.iss).toBe('test-issuer');
    expect(claims.aud).toBe('test-audience');
  });

  it('rejects a token signed for a different audience', async () => {
    const attackerEnv = makeTestEnv({
      jwt: { audience: 'other-audience' },
      accessToken: { ttlSeconds: 900 },
    });
    const attacker = new TokenService(attackerEnv);
    const victim = serviceWith(900);
    const foreignToken = await attacker.signAccessToken(user.id, 'session_1');
    await expect(victim.verifyAccessToken(foreignToken)).rejects.toThrow();
  });

  it('rejects a tampered payload', async () => {
    const service = serviceWith(900);
    const token = await service.signAccessToken(user.id, 'session_1');
    const [header, payload, signature] = token.split('.');
    const decoded = JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8')) as AccessClaims;
    const forged = Buffer.from(JSON.stringify({ ...decoded, sub: 'someone-else' })).toString(
      'base64url',
    );
    const tampered = [header, forged, signature].join('.');
    await expect(service.verifyAccessToken(tampered)).rejects.toThrow();
  });

  it('rejects an expired token', async () => {
    const service = serviceWith(60);
    const token = await service.signAccessToken(user.id, 'session_1');
    vi.useFakeTimers();
    vi.setSystemTime(Date.now() + 61_000);
    try {
      await expect(service.verifyAccessToken(token)).rejects.toThrow();
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects structurally invalid tokens', async () => {
    const service = serviceWith(900);
    await expect(service.verifyAccessToken('garbage')).rejects.toThrow();
    await expect(service.verifyAccessToken('')).rejects.toThrow();
  });

  it('produces a unique jti per token', async () => {
    const service = serviceWith(900);
    const [a, b] = await Promise.all([
      service.verifyAccessToken(await service.signAccessToken(user.id, 'session_1')),
      service.verifyAccessToken(await service.signAccessToken(user.id, 'session_1')),
    ]);
    expect(a.jti).not.toBe(b.jti);
  });
});
