import { beforeEach, describe, expect, it } from 'vitest';
import { AuditLogService } from '../../src/modules/audit-logs/audit-log.service.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import { createUserFixture } from '../utils/rbac-fixtures.js';

const audit = new AuditLogService(prisma);

beforeEach(async () => {
  await resetTestDatabase();
});

describe('AuditLogService.record', () => {
  it('appends a row and returns the whitelisted view', async () => {
    const actorId = await createUserFixture('actor@audit.test.local');

    const event = await audit.record({
      actorUserId: actorId,
      action: 'role.created',
      resourceType: 'role',
      resourceId: 'role-1',
      changes: { name: 'Editor', password: 'leak' },
      meta: { ip: '10.0.0.1', userAgent: 'vitest' },
    });

    expect(event).toMatchObject({
      id: expect.any(String),
      actorUserId: actorId,
      action: 'role.created',
      resourceType: 'role',
      resourceId: 'role-1',
      ip: '10.0.0.1',
      userAgent: 'vitest',
    });

    const stored = await prisma.auditLog.findFirstOrThrow({ orderBy: { id: 'desc' } });
    expect(JSON.parse(JSON.stringify(stored.changes))).toEqual({ name: 'Editor' });
    expect(stored.changes).not.toHaveProperty('password');
  });

  it('never loses the event when the actor is deleted: append-only survives its subject', async () => {
    const actorId = await createUserFixture('doomed@audit.test.local');
    await audit.record({ actorUserId: actorId, action: 'auth.logout', resourceType: 'session' });

    await prisma.user.delete({ where: { id: actorId } });

    const rows = await prisma.auditLog.findMany({ where: { action: 'auth.logout' } });
    expect(rows).toHaveLength(1);
    expect(rows[0]?.actorUserId).toBeNull();
  });

  it('accepts anonymous events (failed logins for unknown accounts)', async () => {
    await audit.record({
      action: 'auth.login.failure',
      resourceType: 'session',
      meta: { ip: '10.0.0.2', userAgent: undefined },
    });

    const stored = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'auth.login.failure' },
    });
    expect(stored.actorUserId).toBeNull();
    expect(stored.ip).toBe('10.0.0.2');
  });
});

describe('AuditLogService.list', () => {
  it('returns newest-first slices by limit and offset', async () => {
    for (let i = 1; i <= 5; i += 1) {
      await audit.record({ action: `test.event-${i}`, resourceType: 'test' });
    }

    const page = await audit.list({ limit: 3 });
    expect(page.map((event) => event.action)).toEqual([
      'test.event-5',
      'test.event-4',
      'test.event-3',
    ]);

    const rest = await audit.list({ limit: 3, offset: 3 });
    expect(rest.map((event) => event.action)).toEqual(['test.event-2', 'test.event-1']);
  });

  it('exposes no update or delete capability: the API is append-only', () => {
    expect(Object.getOwnPropertyNames(AuditLogService.prototype).sort()).toEqual(
      ['constructor', 'list', 'record'].sort(),
    );
  });
});
