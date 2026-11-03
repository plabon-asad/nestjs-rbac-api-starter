import type { PrismaClient } from '../../generated/prisma/client.js';
import type { PasswordService } from '../../modules/auth/services/password.service.js';
import {
  CATALOGUE_PERMISSIONS,
  CATALOGUE_ROLES,
  SUPER_ADMIN_ROLE_NAME,
  validateCatalogue,
} from './rbac-catalogue.js';

export interface SeedRbacOptions {
  readonly superAdmin: {
    readonly email: string;
    readonly password: string;
  };
  readonly passwords: PasswordService;
}

export interface SeedRbacResult {
  readonly permissionCount: number;
  readonly roleCount: number;
  readonly superAdminCreated: boolean;
  /** True when the account already existed, so its stored hash was left untouched. */
  readonly superAdminPasswordPreserved: boolean;
}

/**
 * Brings the RBAC tables up to the checked-in catalogue. Safe to run on every deploy:
 * the bootstrap password is only ever used to create a missing account, never to
 * overwrite an existing one, so rotating it in a secret manager does not lock anyone out.
 */
export async function seedRbac(
  db: PrismaClient,
  options: SeedRbacOptions,
): Promise<SeedRbacResult> {
  const problems = validateCatalogue(CATALOGUE_PERMISSIONS, CATALOGUE_ROLES);
  if (problems.length > 0) {
    throw new Error(`Refusing to seed an inconsistent RBAC catalogue:\n- ${problems.join('\n- ')}`);
  }

  const email = options.superAdmin.email.toLowerCase();
  const passwordHash = await options.passwords.hash(options.superAdmin.password);

  return db.$transaction(async (tx) => {
    for (const entry of CATALOGUE_PERMISSIONS) {
      await tx.permission.upsert({
        where: { key: entry.key },
        create: {
          key: entry.key,
          name: entry.name,
          description: entry.description ?? null,
          resource: entry.resource,
          action: entry.action,
        },
        update: { name: entry.name, description: entry.description ?? null },
      });
    }

    const catalogue = await tx.permission.findMany({ select: { id: true, key: true } });
    const idByKey = new Map(catalogue.map((row) => [row.key, row.id]));

    for (const roleSeed of CATALOGUE_ROLES) {
      const role = await tx.role.upsert({
        where: { name: roleSeed.name },
        create: {
          name: roleSeed.name,
          description: roleSeed.description ?? null,
          isSystem: roleSeed.isSystem,
        },
        // isSystem is never promoted or demoted by a seed: it is decided in code.
        update: { description: roleSeed.description ?? null },
      });

      const wantedKeys = roleSeed.grantsAll
        ? CATALOGUE_PERMISSIONS.map((entry) => entry.key)
        : (roleSeed.permissions ?? []);
      const wantedIds = wantedKeys
        .map((key) => idByKey.get(key))
        .filter((id): id is string => id !== undefined);

      await tx.rolePermission.deleteMany({
        where: { roleId: role.id, NOT: { permissionId: { in: wantedIds } } },
      });
      if (wantedIds.length > 0) {
        await tx.rolePermission.createMany({
          data: wantedIds.map((permissionId) => ({ roleId: role.id, permissionId })),
          skipDuplicates: true,
        });
      }
    }

    const superAdminRole = await tx.role.findUnique({ where: { name: SUPER_ADMIN_ROLE_NAME } });
    if (superAdminRole === null) {
      throw new Error(`System role ${SUPER_ADMIN_ROLE_NAME} disappeared during seeding`);
    }

    let superAdmin = await tx.user.findUnique({ where: { email } });
    const superAdminCreated = superAdmin === null;
    if (superAdmin === null) {
      superAdmin = await tx.user.create({
        data: {
          email,
          passwordHash,
          firstName: 'Super',
          lastName: 'Admin',
          status: 'ACTIVE',
        },
      });
    }

    await tx.userRole.upsert({
      where: { userId_roleId: { userId: superAdmin.id, roleId: superAdminRole.id } },
      create: { userId: superAdmin.id, roleId: superAdminRole.id },
      update: {},
    });

    const permissionCount = await tx.permission.count();
    const roleCount = await tx.role.count();

    return {
      permissionCount,
      roleCount,
      superAdminCreated,
      superAdminPasswordPreserved: !superAdminCreated,
    };
  });
}
