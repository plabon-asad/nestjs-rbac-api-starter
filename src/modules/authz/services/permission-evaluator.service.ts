import { ForbiddenException, Injectable } from '@nestjs/common';
import type { UserStatus } from '../../../generated/prisma/client.js';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import type { PermissionMode } from '../../../common/decorators/require-permissions.decorator.js';

export interface AccessFacts {
  readonly status: UserStatus;
  readonly superAdmin: boolean;
  /** Names of the roles assigned to the user, sorted alphabetically. */
  readonly roleNames: readonly string[];
  readonly permissions: ReadonlySet<string>;
}

/**
 * The single decision function. Kept pure (and exported) so the rules are testable without a
 * database, and so no guard, service or controller can invent its own interpretation.
 */
export function checkAccess(
  facts: AccessFacts | null,
  required: readonly string[],
  mode: PermissionMode,
): boolean {
  if (facts === null || facts.status !== 'ACTIVE') {
    return false;
  }
  if (required.length === 0) {
    return false;
  }
  if (facts.superAdmin) {
    return true;
  }
  return mode === 'and'
    ? required.every((key) => facts.permissions.has(key))
    : required.some((key) => facts.permissions.has(key));
}

@Injectable()
export class PermissionEvaluatorService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Reads the current grant set from the database on every call. Deliberately uncached:
   * revoking a role or deactivating an account has to bite on the next request, and a
   * starter template should not ship a cache whose invalidation the reader cannot see.
   * The returned `permissions` are the effective set: (role grants ∪ ALLOW overrides) \ DENY overrides.
   */
  async factsFor(userId: string): Promise<AccessFacts | null> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        status: true,
        roles: {
          select: {
            role: {
              select: {
                name: true,
                isSystem: true,
                permissions: { select: { permission: { select: { key: true } } } },
              },
            },
          },
        },
        permissionOverrides: {
          select: { effect: true, permission: { select: { key: true } } },
        },
      },
    });
    if (user === null) {
      return null;
    }

    const permissions = new Set<string>();
    const roleNames: string[] = [];
    let superAdmin = false;
    for (const assignment of user.roles) {
      superAdmin = superAdmin || assignment.role.isSystem;
      roleNames.push(assignment.role.name);
      for (const grant of assignment.role.permissions) {
        permissions.add(grant.permission.key);
      }
    }
    for (const override of user.permissionOverrides) {
      if (override.effect === 'ALLOW') {
        permissions.add(override.permission.key);
      } else {
        permissions.delete(override.permission.key);
      }
    }

    return { status: user.status, superAdmin, roleNames: roleNames.sort(), permissions };
  }

  async isAllowed(
    userId: string,
    required: readonly string[],
    mode: PermissionMode = 'and',
  ): Promise<boolean> {
    return checkAccess(await this.factsFor(userId), required, mode);
  }

  async assertAllowed(
    userId: string,
    required: readonly string[],
    mode: PermissionMode = 'and',
  ): Promise<void> {
    if (!(await this.isAllowed(userId, required, mode))) {
      throw new ForbiddenException('Insufficient permissions');
    }
  }

  /**
   * Grant-scope rule: nobody may hand out a permission they do not effectively hold, which is
   * what stops a role editor from promoting themselves by attaching extra grants to a new role.
   */
  async assertCanGrant(userId: string, keys: readonly string[]): Promise<void> {
    if (keys.length === 0) {
      return;
    }
    await this.assertAllowed(userId, keys, 'and');
  }
}
