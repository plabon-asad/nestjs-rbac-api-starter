import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { prisma } from './prisma-test.js';

const passwords = new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });
const DEFAULT_PASSWORD = 'fixture-password-123';

export async function createUserFixture(
  email: string,
  options: { status?: 'ACTIVE' | 'DISABLED' | 'LOCKED'; password?: string } = {},
): Promise<string> {
  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      passwordHash: await passwords.hash(options.password ?? DEFAULT_PASSWORD),
      firstName: 'Rbac',
      lastName: 'Fixture',
      status: options.status ?? 'ACTIVE',
    },
  });
  return user.id;
}

/** `resource.action` rows are always derived, never hand-typed, so fixtures match the real invariant. */
export async function createPermissionFixture(key: string, name?: string): Promise<string> {
  const separator = key.lastIndexOf('.');
  const resource = key.slice(0, separator);
  const action = key.slice(separator + 1);

  const permission = await prisma.permission.create({
    data: { key, name: name ?? key, resource, action },
  });
  return permission.id;
}

export async function createRoleFixture(
  name: string,
  permissionKeys: readonly string[] = [],
  isSystem = false,
): Promise<string> {
  const role = await prisma.role.create({ data: { name, isSystem } });
  if (permissionKeys.length > 0) {
    const permissions = await prisma.permission.findMany({
      where: { key: { in: [...permissionKeys] } },
      select: { id: true },
    });
    await prisma.rolePermission.createMany({
      data: permissions.map((permission) => ({ roleId: role.id, permissionId: permission.id })),
    });
  }
  return role.id;
}

export async function grantRole(userId: string, roleName: string): Promise<void> {
  const role = await prisma.role.findUniqueOrThrow({ where: { name: roleName } });
  await prisma.userRole.create({ data: { userId, roleId: role.id } });
}
