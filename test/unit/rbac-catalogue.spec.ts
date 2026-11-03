import { describe, expect, it } from 'vitest';
import {
  CATALOGUE_ROLES,
  CATALOGUE_PERMISSIONS,
  SUPER_ADMIN_ROLE_NAME,
  validateCatalogue,
} from '../../src/database/seeds/rbac-catalogue.js';

describe('RBAC permission catalogue', () => {
  it('is valid by its own invariant checks', () => {
    expect(validateCatalogue(CATALOGUE_PERMISSIONS, CATALOGUE_ROLES)).toEqual([]);
  });

  it('derives every key from resource.action', () => {
    for (const permission of CATALOGUE_PERMISSIONS) {
      expect(permission.key).toBe(`${permission.resource}.${permission.action}`);
    }
  });

  it('contains no duplicate keys, resources or actions', () => {
    const keys = CATALOGUE_PERMISSIONS.map((permission) => permission.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('marks exactly one system role, named SUPER_ADMIN, holding every permission', () => {
    const systemRoles = CATALOGUE_ROLES.filter((role) => role.isSystem);
    expect(systemRoles).toHaveLength(1);
    expect(systemRoles[0]?.name).toBe(SUPER_ADMIN_ROLE_NAME);
    expect(systemRoles[0]?.grantsAll).toBe(true);
  });

  it('grants each non-system role only permissions that exist in the catalogue', () => {
    const knownKeys = new Set(CATALOGUE_PERMISSIONS.map((permission) => permission.key));
    const problems = CATALOGUE_ROLES.filter((role) => !role.grantsAll)
      .flatMap((role) => role.permissions ?? [])
      .filter((key) => !knownKeys.has(key));

    expect(problems).toEqual([]);
  });

  it('reports every defect at once instead of stopping at the first', () => {
    const problems = validateCatalogue(
      [
        { key: 'users.read', name: 'Read users', resource: 'users', action: 'read' },
        { key: 'wrong.key', name: 'Broken', resource: 'roles', action: 'read' },
        { key: 'users.read', name: 'Duplicate', resource: 'users', action: 'read' },
      ],
      [{ name: 'GHOST', isSystem: false, permissions: ['roles.does-not-exist'] }],
    );

    expect(problems).toHaveLength(3);
    expect(problems.join('\n')).toContain('wrong.key');
    expect(problems.join('\n')).toContain('duplicate');
    expect(problems.join('\n')).toContain('GHOST');
  });
});
