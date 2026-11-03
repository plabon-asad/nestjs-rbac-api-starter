import type { Prisma } from '../../../generated/prisma/client.js';

export const roleWithPermissions = {
  permissions: { include: { permission: true } },
} satisfies Prisma.RoleInclude;

export type RoleWithPermissions = Prisma.RoleGetPayload<{
  include: typeof roleWithPermissions;
}>;

export interface RoleView {
  readonly id: string;
  readonly name: string;
  readonly description: string | null;
  readonly isSystem: boolean;
  readonly permissionKeys: readonly string[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export function toRoleView(role: RoleWithPermissions): RoleView {
  return {
    id: role.id,
    name: role.name,
    description: role.description,
    isSystem: role.isSystem,
    permissionKeys: role.permissions
      .map((grant) => grant.permission.key)
      .sort((left, right) => left.localeCompare(right)),
    createdAt: role.createdAt,
    updatedAt: role.updatedAt,
  };
}
