import 'dotenv/config';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { loadAppEnv } from '../../src/config/app.config.js';
import { PrismaService } from '../../src/database/prisma/prisma.service.js';

// Uses TEST_DATABASE_URL when set (points at rbac_test), else DATABASE_URL.
const env = loadAppEnv({
  ...process.env,
  DATABASE_URL: process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? '',
});

const prisma = new PrismaService(env);

beforeAll(async () => {
  await prisma.$connect();
});

afterAll(async () => {
  await prisma.$disconnect();
});

describe('Prisma connectivity', () => {
  it(`connects to the ${env.database.provider} test database`, async () => {
    // The mariadb adapter surfaces integer literals as BigInt; pg as number.
    const result = await prisma.$queryRaw<{ ok: number | bigint }[]>`SELECT 1 AS ok`;
    expect(Number(result[0]?.ok)).toBe(1);
  });

  it('has all RBAC tables present (migrations applied)', async () => {
    for (const table of [
      'users',
      'roles',
      'permissions',
      'user_roles',
      'role_permissions',
      'user_permission_overrides',
      'refresh_tokens',
      'password_reset_tokens',
      'audit_logs',
    ]) {
      await expect(
        prisma.$queryRawUnsafe<unknown[]>(`SELECT 1 FROM ${table} LIMIT 0`),
      ).resolves.toBeDefined();
    }
  });
});
