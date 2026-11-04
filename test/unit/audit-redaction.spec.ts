import { describe, expect, it } from 'vitest';
import { redactChanges } from '../../src/modules/audit-logs/redaction.js';

describe('redactChanges', () => {
  it('drops sensitive keys at every depth', () => {
    const input = {
      email: 'user@test.local',
      currentPassword: 'secret-1',
      newPassword: 'secret-2',
      role: {
        name: 'EDITOR',
        permissions: [{ key: 'roles.read', token: 'abc', refreshToken: 'def' }],
      },
      passwordHash: '$argon2id$...',
      authorization: 'Bearer ...',
      cookie: 'refresh_token=...',
    };

    expect(redactChanges(input)).toEqual({
      email: 'user@test.local',
      role: {
        name: 'EDITOR',
        permissions: [{ key: 'roles.read' }],
      },
    });
  });

  it('keeps benign values untouched', () => {
    const input = { status: 'DISABLED', attempts: 3, active: true, clearedAt: null };
    expect(redactChanges(input)).toEqual(input);
  });

  it('treats a missing or non-object payload as nothing to record', () => {
    expect(redactChanges(undefined)).toEqual({});
    expect(redactChanges('plain string' as unknown as Record<string, unknown>)).toEqual({});
  });

  it('does not mutate the input object', () => {
    const input = { password: 'x', kept: 'y' };
    redactChanges(input);
    expect(input).toEqual({ password: 'x', kept: 'y' });
  });

  it('stops at a bounded depth instead of recursing forever', () => {
    let deep: Record<string, unknown> = { password: 'x' };
    for (let i = 0; i < 20; i += 1) {
      deep = { nested: deep };
    }
    const result = redactChanges(deep);
    expect(JSON.stringify(result)).not.toContain('"password"');
  });
});
