import type { UserStatus } from '../../../generated/prisma/client.js';

export interface UserWithRoleRecords {
  readonly id: string;
  readonly email: string;
  readonly firstName: string;
  readonly lastName: string;
  readonly status: UserStatus;
  readonly createdAt: Date;
  readonly updatedAt: Date;
  readonly roles: readonly { readonly role: { readonly name: string } }[];
}

/** Whitelisted projection — credential and lockout columns never leave the service layer. */
export interface UserAdminView {
  readonly id: string;
  readonly email: string;
  readonly firstName: string;
  readonly lastName: string;
  readonly status: UserStatus;
  readonly roleNames: readonly string[];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export function toUserAdminView(user: UserWithRoleRecords): UserAdminView {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    status: user.status,
    roleNames: user.roles.map((assignment) => assignment.role.name).sort(),
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}
