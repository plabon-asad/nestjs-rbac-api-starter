export const SUPER_ADMIN_ROLE_NAME = 'SUPER_ADMIN';

const SLUG_PATTERN = /^[a-z0-9]+(?:[-_][a-z0-9]+)*$/;

/** Resource and action segments must be slugs so that `resource.action` keys stay parseable. */
export function isPermissionSlug(value: string): boolean {
  return SLUG_PATTERN.test(value);
}

export interface PermissionSeed {
  readonly key: string;
  readonly name: string;
  readonly description?: string | undefined;
  readonly resource: string;
  readonly action: string;
}

export interface RoleSeed {
  readonly name: string;
  readonly description?: string | undefined;
  readonly isSystem: boolean;
  /** The system role always mirrors the whole catalogue, including future entries. */
  readonly grantsAll?: boolean | undefined;
  readonly permissions?: readonly string[] | undefined;
}

function permission(
  resource: string,
  action: string,
  name: string,
  description: string,
): PermissionSeed {
  return { key: `${resource}.${action}`, name, description, resource, action };
}

/**
 * The permission catalogue the API is built against. Route metadata in later phases
 * references these exact keys, so adding one is a code change, not a runtime edit.
 */
export const CATALOGUE_PERMISSIONS: readonly PermissionSeed[] = [
  permission('users', 'read', 'View users', 'Read user profiles and account status'),
  permission('users', 'create', 'Create users', 'Invite or create new accounts'),
  permission('users', 'update', 'Update users', 'Change profile fields and account status'),
  permission('users', 'delete', 'Delete users', 'Permanently remove an account'),
  permission('users', 'assign-roles', 'Assign roles', 'Grant or revoke roles on a user'),
  permission('roles', 'read', 'View roles', 'List roles and their grants'),
  permission('roles', 'create', 'Create roles', 'Define a new role'),
  permission('roles', 'update', 'Update roles', 'Rename a role or change its grants'),
  permission('roles', 'delete', 'Delete roles', 'Remove an unused role'),
  permission('permissions', 'read', 'View permissions', 'List the permission catalogue'),
  permission('permissions', 'create', 'Create permissions', 'Add a permission to the catalogue'),
  permission('permissions', 'update', 'Update permissions', 'Rename or redescribe a permission'),
  permission('permissions', 'delete', 'Delete permissions', 'Remove an unused permission'),
  permission('permission-overrides', 'read', 'View overrides', 'Inspect per-user ALLOW/DENY rows'),
  permission(
    'permission-overrides',
    'manage',
    'Manage overrides',
    'Set or reset per-user ALLOW/DENY overrides',
  ),
  permission('audit-logs', 'read', 'View audit logs', 'Read the security event trail'),
  permission('sessions', 'revoke', 'Revoke sessions', 'Force-sign-out another account'),
];

export const CATALOGUE_ROLES: readonly RoleSeed[] = [
  {
    name: SUPER_ADMIN_ROLE_NAME,
    description: 'Full access to every resource. Protected: cannot be renamed, deleted or limited.',
    isSystem: true,
    grantsAll: true,
  },
  {
    name: 'USER_ADMIN',
    description: 'Manages accounts, roles and sessions without being able to remove accounts.',
    isSystem: false,
    permissions: [
      'users.read',
      'users.create',
      'users.update',
      'users.assign-roles',
      'roles.read',
      'permissions.read',
      'permission-overrides.read',
      'audit-logs.read',
      'sessions.revoke',
    ],
  },
  {
    name: 'READ_ONLY',
    description: 'Observes the system; grants no write or privilege-changing capability.',
    isSystem: false,
    permissions: [
      'users.read',
      'roles.read',
      'permissions.read',
      'permission-overrides.read',
      'audit-logs.read',
    ],
  },
];

/**
 * Returns one message per defect (never short-circuits) so a broken catalogue is
 * fully described in a single run. An empty array means the catalogue is consistent.
 */
export function validateCatalogue(
  permissions: readonly PermissionSeed[],
  roles: readonly RoleSeed[],
): string[] {
  const problems: string[] = [];
  const seen = new Set<string>();
  const keys = new Set<string>();

  for (const entry of permissions) {
    if (entry.key !== `${entry.resource}.${entry.action}`) {
      problems.push(
        `permission ${entry.key}: key does not match ${entry.resource}.${entry.action}`,
      );
    }
    if (!isPermissionSlug(entry.resource)) {
      problems.push(`permission ${entry.key}: resource '${entry.resource}' is not a slug`);
    }
    if (!isPermissionSlug(entry.action)) {
      problems.push(`permission ${entry.key}: action '${entry.action}' is not a slug`);
    }
    if (seen.has(entry.key)) {
      problems.push(`permission ${entry.key}: duplicate key in the catalogue`);
    }
    seen.add(entry.key);
    keys.add(entry.key);
  }

  const roleNames = new Set<string>();
  for (const role of roles) {
    if (roleNames.has(role.name)) {
      problems.push(`role ${role.name}: duplicate role in the catalogue`);
    }
    roleNames.add(role.name);
    if (role.grantsAll) continue;

    for (const key of role.permissions ?? []) {
      if (!keys.has(key)) {
        problems.push(`role ${role.name}: references unknown permission ${key}`);
      }
    }
  }

  return problems;
}
