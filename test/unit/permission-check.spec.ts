import { describe, expect, it } from 'vitest';
import {
  checkAccess,
  type AccessFacts,
} from '../../src/modules/authz/services/permission-evaluator.service.js';

function facts(overrides: Partial<AccessFacts> = {}): AccessFacts {
  return {
    status: 'ACTIVE',
    superAdmin: false,
    permissions: new Set<string>(['roles.read']),
    ...overrides,
  };
}

describe('checkAccess', () => {
  it('denies an unknown account', () => {
    expect(checkAccess(null, ['roles.read'], 'and')).toBe(false);
  });

  it('denies any inactive account even with the permission granted', () => {
    for (const status of ['DISABLED', 'LOCKED'] as const) {
      expect(checkAccess(facts({ status }), ['roles.read'], 'and')).toBe(false);
    }
  });

  it('denies an empty requirement list rather than treating it as satisfied', () => {
    expect(checkAccess(facts(), [], 'and')).toBe(false);
    expect(checkAccess(facts(), [], 'or')).toBe(false);
  });

  it('AND mode requires every permission', () => {
    expect(checkAccess(facts(), ['roles.read'], 'and')).toBe(true);
    expect(checkAccess(facts(), ['roles.read', 'roles.delete'], 'and')).toBe(false);
  });

  it('OR mode requires at least one permission', () => {
    expect(checkAccess(facts(), ['roles.read', 'roles.delete'], 'or')).toBe(true);
    expect(checkAccess(facts(), ['roles.delete', 'roles.create'], 'or')).toBe(false);
  });

  it('ignores permissions that were revoked', () => {
    const granted = new Set(['roles.read']);
    const afterRevoke = facts({ permissions: granted });
    expect(checkAccess(afterRevoke, ['roles.read'], 'and')).toBe(true);

    granted.delete('roles.read');
    expect(checkAccess(afterRevoke, ['roles.read'], 'and')).toBe(false);
  });

  it('grants everything to a system role holder, including an empty permission set', () => {
    const superAdmin = facts({ superAdmin: true, permissions: new Set<string>() });
    expect(checkAccess(superAdmin, ['anything.at-all'], 'and')).toBe(true);
  });

  it('never lets the super admin bypass override the account status', () => {
    expect(
      checkAccess(facts({ superAdmin: true, status: 'DISABLED' }), ['roles.read'], 'and'),
    ).toBe(false);
  });
});
