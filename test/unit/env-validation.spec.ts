import { describe, expect, it } from 'vitest';
import { parseEnv } from '../../src/config/env.validation.js';

function baseEnv(overrides: Record<string, string> = {}): Record<string, string> {
  return {
    NODE_ENV: 'development',
    PORT: '3000',
    DATABASE_PROVIDER: 'postgresql',
    DATABASE_URL: 'postgresql://rbac:secret@localhost:5432/rbac_dev',
    JWT_ACCESS_SECRET: 'x'.repeat(48),
    JWT_ISSUER: 'test-issuer',
    JWT_AUDIENCE: 'test-audience',
    ACCESS_TOKEN_TTL_SECONDS: '900',
    REFRESH_TOKEN_TTL_DAYS: '14',
    COOKIE_SECURE: 'false',
    AUTH_THROTTLE_LIMIT: '10',
    AUTH_THROTTLE_TTL_SECONDS: '60',
    SUPER_ADMIN_EMAIL: 'admin@example.com',
    SUPER_ADMIN_PASSWORD: 'a-strong-unique-password',
    ...overrides,
  };
}

describe('parseEnv', () => {
  it('accepts a valid development environment and coerces types', () => {
    const config = parseEnv(baseEnv());
    expect(config.port).toBe(3000);
    expect(config.database.provider).toBe('postgresql');
    expect(config.accessToken.ttlSeconds).toBe(900);
    expect(config.refreshToken.ttlDays).toBe(14);
    expect(config.isProduction).toBe(false);
  });

  it('rejects an unknown DATABASE_PROVIDER', () => {
    expect(() => parseEnv(baseEnv({ DATABASE_PROVIDER: 'sqlite' }))).toThrowError(
      /DATABASE_PROVIDER/,
    );
  });

  it('rejects a JWT secret shorter than 32 characters', () => {
    expect(() => parseEnv(baseEnv({ JWT_ACCESS_SECRET: 'short' }))).toThrowError(
      /JWT_ACCESS_SECRET/,
    );
  });

  it('rejects an empty JWT secret', () => {
    expect(() => parseEnv(baseEnv({ JWT_ACCESS_SECRET: '' }))).toThrowError(/JWT_ACCESS_SECRET/);
  });

  it('requires SUPER_ADMIN_EMAIL to be a valid email', () => {
    expect(() => parseEnv(baseEnv({ SUPER_ADMIN_EMAIL: 'not-an-email' }))).toThrowError(
      /SUPER_ADMIN_EMAIL/,
    );
  });

  it('rejects a DATABASE_URL scheme that does not match DATABASE_PROVIDER', () => {
    expect(() =>
      parseEnv(baseEnv({ DATABASE_URL: 'mysql://rbac:secret@localhost:3306/rbac_dev' })),
    ).toThrowError(/DATABASE_URL/);
  });

  it('rejects the placeholder super admin password in production', () => {
    expect(() =>
      parseEnv(
        baseEnv({
          NODE_ENV: 'production',
          COOKIE_SECURE: 'true',
          SUPER_ADMIN_PASSWORD: 'change-this-secure-password',
        }),
      ),
    ).toThrowError(/SUPER_ADMIN_PASSWORD/);
  });

  it('rejects missing JWT secret in production', () => {
    expect(() =>
      parseEnv(baseEnv({ NODE_ENV: 'production', COOKIE_SECURE: 'true', JWT_ACCESS_SECRET: '' })),
    ).toThrowError(/JWT_ACCESS_SECRET/);
  });

  it('requires COOKIE_SECURE in production', () => {
    expect(() =>
      parseEnv(baseEnv({ NODE_ENV: 'production', COOKIE_SECURE: 'false' })),
    ).toThrowError(/COOKIE_SECURE/);
  });

  it('aggregates every problem field into one error instead of failing on the first', () => {
    try {
      parseEnv(baseEnv({ JWT_ACCESS_SECRET: 'short', DATABASE_PROVIDER: 'oracle' }));
      expect.unreachable('parseEnv should have thrown');
    } catch (error) {
      const message = (error as Error).message;
      expect(message).toMatch(/JWT_ACCESS_SECRET/);
      expect(message).toMatch(/DATABASE_PROVIDER/);
    }
  });
});
