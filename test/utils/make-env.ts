import type { AppEnvironment } from '../../src/config/env.validation.js';

export function makeTestEnv(overrides: DeepPartial<AppEnvironment> = {}): AppEnvironment {
  const base: AppEnvironment = {
    nodeEnv: 'test',
    isProduction: false,
    port: 0,
    database: {
      provider: 'postgresql',
      url: process.env.TEST_DATABASE_URL ?? '',
    },
    jwt: {
      accessSecret: 'unit-test-secret-which-is-definitely-long-enough-32+',
      issuer: 'test-issuer',
      audience: 'test-audience',
    },
    accessToken: { ttlSeconds: 900 },
    refreshToken: { ttlDays: 14 },
    cookieSecure: false,
    docsEnabled: false,
    throttle: { limit: 10, ttlSeconds: 60 },
    superAdmin: { email: 'admin@example.com', password: 'test-password-1234' },
  };
  return merge(base, overrides) as AppEnvironment;
}

type DeepPartial<T> = { [K in keyof T]?: T[K] extends object ? DeepPartial<T[K]> : T[K] };

function merge(base: object, overrides: object): object {
  const out: Record<string, unknown> = { ...(base as Record<string, unknown>) };
  for (const [key, value] of Object.entries(overrides as Record<string, unknown>)) {
    const current = out[key];
    if (value && typeof value === 'object' && current && typeof current === 'object') {
      out[key] = merge(current, value);
    } else if (value !== undefined) {
      out[key] = value;
    }
  }
  return out;
}
