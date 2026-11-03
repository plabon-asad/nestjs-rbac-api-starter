import type { Permission } from '../../../generated/prisma/client.js';

export interface PermissionView {
  readonly id: string;
  readonly key: string;
  readonly name: string;
  readonly description: string | null;
  readonly resource: string;
  readonly action: string;
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export function toPermissionView(permission: Permission): PermissionView {
  return {
    id: permission.id,
    key: permission.key,
    name: permission.name,
    description: permission.description,
    resource: permission.resource,
    action: permission.action,
    createdAt: permission.createdAt,
    updatedAt: permission.updatedAt,
  };
}
