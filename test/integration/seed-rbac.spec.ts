import { beforeAll, describe, expect, it } from 'vitest';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { CATALOGUE_PERMISSIONS } from '../../src/database/seeds/rbac-catalogue.js';
import { seedRbac } from '../../src/database/seeds/seed-rbac.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';

const SUPER_EMAIL = 'root@seed.test.local';
const SUPER_PASSWORD = 'seed-super-password-123';

const fastPasswords = () => new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });

function runSeed() {
  return seedRbac(prisma, {
    superAdmin: { email: SUPER_EMAIL, password: SUPER_PASSWORD },
    passwords: fastPasswords(),
  });
}

beforeAll(async () => {
  await resetTestDatabase();
  await runSeed();
});

describe('seedRbac', () => {
  it('materializes the full catalogue and the super admin account', async () => {
    const [permissions, roles, user] = await Promise.all([
      prisma.permission.findMany(),
      prisma.role.findMany({ where: { isSystem: true } }),
      prisma.user.findUnique({
        where: { email: SUPER_EMAIL },
        include: { roles: { include: { role: true } } },
      }),
    ]);

    expect(permissions).toHaveLength(CATALOGUE_PERMISSIONS.length);
    expect(roles).toHaveLength(1);
    expect(user).not.toBeNull();
    expect(user?.email).toBe(SUPER_EMAIL);
    expect(user?.status).toBe('ACTIVE');
    expect(user?.roles.map((row) => row.role.name)).toContain('SUPER_ADMIN');
  });

  it('never stores the bootstrap password itself', async () => {
    const user = await prisma.user.findUnique({ where: { email: SUPER_EMAIL } });
    expect(user?.passwordHash).not.toContain(SUPER_PASSWORD);
    expect(user?.passwordHash.startsWith('$argon2')).toBe(true);
  });

  it('grants the system role every permission in the catalogue', async () => {
    const superRole = await prisma.role.findUnique({
      where: { name: 'SUPER_ADMIN' },
      include: { permissions: true },
    });
    expect(superRole?.permissions).toHaveLength(CATALOGUE_PERMISSIONS.length);
  });

  it('is idempotent: a second run changes nothing and creates no duplicates', async () => {
    const before = await snapshot();
    const second = await runSeed();
    const after = await snapshot();

    expect(after).toEqual(before);
    expect(second.superAdminCreated).toBe(false);
  });

  it('preserves a password an operator changed after the first seed', async () => {
    const replacement = await fastPasswords().hash('operator-chosen-password-999');
    await prisma.user.update({
      where: { email: SUPER_EMAIL },
      data: { passwordHash: replacement },
    });

    const result = await runSeed();
    const user = await prisma.user.findUnique({ where: { email: SUPER_EMAIL } });

    expect(result.superAdminPasswordPreserved).toBe(true);
    expect(user?.passwordHash).toBe(replacement);
  });

  it('adopts permissions added to the catalogue after the role was created', async () => {
    await prisma.permission.delete({ where: { key: 'users.delete' } });
    await runSeed();

    const superRole = await prisma.role.findUnique({
      where: { name: 'SUPER_ADMIN' },
      include: { permissions: true },
    });
    expect(superRole?.permissions).toHaveLength(CATALOGUE_PERMISSIONS.length);
    await expect(
      prisma.permission.findUnique({ where: { key: 'users.delete' } }),
    ).resolves.not.toBeNull();
  });

  it('reuses existing users with the bootstrap email instead of failing on the unique index', async () => {
    const taken = 'shared@seed.test.local';
    await prisma.user.create({
      data: {
        email: taken,
        passwordHash: await fastPasswords().hash('preexisting-password-1'),
        firstName: 'Existing',
        lastName: 'Account',
        status: 'DISABLED',
      },
    });

    const result = await seedRbac(prisma, {
      superAdmin: { email: taken, password: SUPER_PASSWORD },
      passwords: fastPasswords(),
    });

    const user = await prisma.user.findUnique({ where: { email: taken } });
    expect(result.superAdminCreated).toBe(false);
    expect(user?.status).toBe('DISABLED');
    expect(user?.firstName).toBe('Existing');
  });
});

async function snapshot() {
  const [permissions, roles, users, grants, memberships] = await Promise.all([
    prisma.permission.count(),
    prisma.role.count(),
    prisma.user.count(),
    prisma.rolePermission.count(),
    prisma.userRole.count(),
  ]);
  return { permissions, roles, users, grants, memberships };
}
