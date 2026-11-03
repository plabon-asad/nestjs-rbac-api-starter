import 'dotenv/config';
import { loadAppEnv } from '../../src/config/app.config.js';
import { PrismaService } from '../../src/database/prisma/prisma.service.js';

// Single shared connection to the isolated test database for all integration/e2e suites.
export const testEnv = loadAppEnv({
  ...process.env,
  DATABASE_URL: process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL ?? '',
});

export const prisma = new PrismaService(testEnv);

const TABLES = [
  'audit_logs',
  'password_reset_tokens',
  'refresh_tokens',
  'user_permission_overrides',
  'role_permissions',
  'user_roles',
  'permissions',
  'roles',
  'users',
];

export async function resetTestDatabase(): Promise<void> {
  if (testEnv.database.provider === 'postgresql') {
    for (const table of TABLES) {
      await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${table} RESTART IDENTITY CASCADE`);
    }
  } else {
    await prisma.$executeRawUnsafe('SET FOREIGN_KEY_CHECKS = 0');
    for (const table of TABLES) {
      await prisma.$executeRawUnsafe(`TRUNCATE TABLE ${table}`);
    }
    await prisma.$executeRawUnsafe('SET FOREIGN_KEY_CHECKS = 1');
  }
}
