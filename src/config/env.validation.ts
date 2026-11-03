import { z } from 'zod';

const PLACEHOLDER_SUPER_ADMIN_PASSWORD = 'change-this-secure-password';

const envRecordSchema = z
  .object({
    NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
    PORT: z.coerce.number().int().min(1).max(65535).default(3000),
    DATABASE_PROVIDER: z.enum(['postgresql', 'mysql']),
    DATABASE_URL: z.string().min(1),
    JWT_ACCESS_SECRET: z.string().min(32, 'must be at least 32 characters'),
    JWT_ISSUER: z.string().min(1),
    JWT_AUDIENCE: z.string().min(1),
    ACCESS_TOKEN_TTL_SECONDS: z.coerce.number().int().min(60).max(3600).default(900),
    REFRESH_TOKEN_TTL_DAYS: z.coerce.number().int().min(1).max(90).default(14),
    COOKIE_SECURE: z
      .enum(['true', 'false'])
      .default('false')
      .transform((value) => value === 'true'),
    AUTH_THROTTLE_LIMIT: z.coerce.number().int().min(1).default(10),
    AUTH_THROTTLE_TTL_SECONDS: z.coerce.number().int().min(1).default(60),
    SUPER_ADMIN_EMAIL: z.email(),
    SUPER_ADMIN_PASSWORD: z.string().min(1),
  })
  .superRefine((value, ctx) => {
    if (value.DATABASE_PROVIDER === 'postgresql') {
      if (!/^postgres(ql)?:\/\//.test(value.DATABASE_URL)) {
        ctx.addIssue({
          code: 'custom',
          message:
            'DATABASE_URL must be a postgresql:// (or postgres://) URL for DATABASE_PROVIDER=postgresql',
          path: ['DATABASE_URL'],
        });
      }
    } else if (!/^mysql:\/\//.test(value.DATABASE_URL)) {
      ctx.addIssue({
        code: 'custom',
        message: 'DATABASE_URL must be a mysql:// URL for DATABASE_PROVIDER=mysql',
        path: ['DATABASE_URL'],
      });
    }

    if (value.NODE_ENV === 'production') {
      if (!value.COOKIE_SECURE) {
        ctx.addIssue({
          code: 'custom',
          message: 'COOKIE_SECURE must be true in production',
          path: ['COOKIE_SECURE'],
        });
      }
      if (value.SUPER_ADMIN_PASSWORD === PLACEHOLDER_SUPER_ADMIN_PASSWORD) {
        ctx.addIssue({
          code: 'custom',
          message: 'SUPER_ADMIN_PASSWORD still uses the documented placeholder value',
          path: ['SUPER_ADMIN_PASSWORD'],
        });
      }
    }
  });

export interface AppEnvironment {
  readonly nodeEnv: 'development' | 'production' | 'test';
  readonly isProduction: boolean;
  readonly port: number;
  readonly database: {
    readonly provider: 'postgresql' | 'mysql';
    readonly url: string;
  };
  readonly jwt: {
    readonly accessSecret: string;
    readonly issuer: string;
    readonly audience: string;
  };
  readonly accessToken: { readonly ttlSeconds: number };
  readonly refreshToken: { readonly ttlDays: number };
  readonly cookieSecure: boolean;
  readonly throttle: { readonly limit: number; readonly ttlSeconds: number };
  readonly superAdmin: { readonly email: string; readonly password: string };
}

export class EnvironmentValidationError extends Error {
  constructor(readonly issues: ReadonlyArray<string>) {
    super(
      `Invalid environment configuration:\n${issues.map((issue) => `  - ${issue}`).join('\n')}`,
    );
    this.name = 'EnvironmentValidationError';
  }
}

export function parseEnv(record: Record<string, string | undefined>): AppEnvironment {
  const stripped: Record<string, string> = {};
  for (const [key, value] of Object.entries(record)) {
    if (value !== undefined && value !== '') {
      stripped[key] = value;
    }
  }

  const result = envRecordSchema.safeParse(stripped);
  if (!result.success) {
    const issues = result.error.issues.map((issue) => {
      const path = issue.path.join('.') || 'environment';
      return `${path}: ${issue.message}`;
    });
    throw new EnvironmentValidationError(issues);
  }

  const env = result.data;
  return {
    nodeEnv: env.NODE_ENV,
    isProduction: env.NODE_ENV === 'production',
    port: env.PORT,
    database: { provider: env.DATABASE_PROVIDER, url: env.DATABASE_URL },
    jwt: {
      accessSecret: env.JWT_ACCESS_SECRET,
      issuer: env.JWT_ISSUER,
      audience: env.JWT_AUDIENCE,
    },
    accessToken: { ttlSeconds: env.ACCESS_TOKEN_TTL_SECONDS },
    refreshToken: { ttlDays: env.REFRESH_TOKEN_TTL_DAYS },
    cookieSecure: env.COOKIE_SECURE,
    throttle: { limit: env.AUTH_THROTTLE_LIMIT, ttlSeconds: env.AUTH_THROTTLE_TTL_SECONDS },
    superAdmin: { email: env.SUPER_ADMIN_EMAIL, password: env.SUPER_ADMIN_PASSWORD },
  };
}
