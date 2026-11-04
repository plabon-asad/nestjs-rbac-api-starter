import { beforeEach, describe, expect, it } from 'vitest';
import { BadRequestException, ConflictException, NotFoundException } from '@nestjs/common';
import type { RequestMeta } from '../../src/common/interfaces/request-meta.interface.js';
import { AuditLogService } from '../../src/modules/audit-logs/audit-log.service.js';
import { PermissionsService } from '../../src/modules/permissions/services/permissions.service.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';

const META: RequestMeta = { ip: '127.0.0.1', userAgent: 'permissions-service-spec' };
const service = new PermissionsService(prisma, new AuditLogService(prisma));

let actorId: string;

beforeEach(async () => {
  await resetTestDatabase();
  const actor = await prisma.user.create({
    data: {
      email: 'actor@permissions.test.local',
      passwordHash: 'not-a-real-hash',
      firstName: 'Act',
      lastName: 'Or',
    },
  });
  actorId = actor.id;
});

describe('PermissionsService.create', () => {
  it('derives the key from resource and action', async () => {
    const permission = await service.create(
      {
        resource: 'invoices',
        action: 'settle',
        name: 'Settle invoices',
        description: 'Mark an invoice as settled',
      },
      actorId,
      META,
    );

    expect(permission).toMatchObject({
      key: 'invoices.settle',
      resource: 'invoices',
      action: 'settle',
      name: 'Settle invoices',
      description: 'Mark an invoice as settled',
    });
  });

  it('records a permission.created audit event with the derived key', async () => {
    const created = await service.create(
      { resource: 'invoices', action: 'settle', name: 'Settle' },
      actorId,
      META,
    );

    const events = await prisma.auditLog.findMany({ where: { action: 'permission.created' } });
    expect(events).toHaveLength(1);
    expect(events[0]?.actorUserId).toBe(actorId);
    expect(events[0]?.resourceType).toBe('permission');
    expect(events[0]?.resourceId).toBe(created.id);
    expect(events[0]?.changes).toMatchObject({ key: 'invoices.settle' });
  });

  it('does not audit a rejected create', async () => {
    await expect(
      service.create(
        { resource: 'in voices', action: 'settle', name: 'Bad resource' },
        actorId,
        META,
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(prisma.auditLog.count()).resolves.toBe(0);
  });

  it('rejects a second permission for the same resource and action', async () => {
    await service.create({ resource: 'invoices', action: 'settle', name: 'Settle' }, actorId, META);

    await expect(
      service.create(
        { resource: 'invoices', action: 'settle', name: 'Settle again' },
        actorId,
        META,
      ),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('rejects slugs that would not produce a well-formed key', async () => {
    await expect(
      service.create(
        { resource: 'in voices', action: 'settle', name: 'Bad resource' },
        actorId,
        META,
      ),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(
      service.create({ resource: 'users', action: 'Read', name: 'Bad action' }, actorId, META),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(prisma.permission.count()).resolves.toBe(0);
  });
});

describe('PermissionsService reads', () => {
  it('lists permissions ordered by key', async () => {
    await service.create(
      { resource: 'users', action: 'write', name: 'Write users' },
      actorId,
      META,
    );
    await service.create({ resource: 'users', action: 'read', name: 'Read users' }, actorId, META);

    const permissions = await service.list();
    expect(permissions.map((permission) => permission.key)).toEqual(['users.read', 'users.write']);
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(service.findById('missing-permission-id')).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('PermissionsService.update', () => {
  it('edits the display fields without touching the key or the grants', async () => {
    const created = await service.create(
      { resource: 'users', action: 'read', name: 'Read users' },
      actorId,
      META,
    );
    const role = await prisma.role.create({ data: { name: 'Viewer' } });
    await prisma.rolePermission.create({ data: { roleId: role.id, permissionId: created.id } });

    const updated = await service.update(
      created.id,
      { name: 'View users', description: 'read-only' },
      actorId,
      META,
    );

    expect(updated.id).toBe(created.id);
    expect(updated.key).toBe('users.read');
    expect(updated.resource).toBe('users');
    expect(updated.action).toBe('read');
    expect(updated.name).toBe('View users');
    expect(updated.description).toBe('read-only');
    await expect(
      prisma.rolePermission.count({ where: { permissionId: created.id } }),
    ).resolves.toBe(1);
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(service.update('missing-id', { name: 'x' }, actorId, META)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('PermissionsService.remove', () => {
  it('deletes an unreferenced permission', async () => {
    const created = await service.create(
      { resource: 'users', action: 'read', name: 'Read users' },
      actorId,
      META,
    );
    await service.remove(created.id, actorId, META);

    await expect(prisma.permission.findUnique({ where: { id: created.id } })).resolves.toBeNull();
    await expect(
      prisma.auditLog.findFirst({ where: { action: 'permission.deleted' } }),
    ).resolves.toMatchObject({ actorUserId: actorId, resourceId: created.id });
  });

  it('refuses to delete a permission still granted to a role', async () => {
    const created = await service.create(
      { resource: 'users', action: 'read', name: 'Read users' },
      actorId,
      META,
    );
    const role = await prisma.role.create({ data: { name: 'Viewer' } });
    await prisma.rolePermission.create({ data: { roleId: role.id, permissionId: created.id } });

    await expect(service.remove(created.id, actorId, META)).rejects.toBeInstanceOf(
      ConflictException,
    );
    await expect(
      prisma.permission.findUnique({ where: { id: created.id } }),
    ).resolves.not.toBeNull();
  });

  it('refuses to delete a permission targeted by a user override', async () => {
    const created = await service.create(
      { resource: 'users', action: 'read', name: 'Read users' },
      actorId,
      META,
    );
    const user = await prisma.user.create({
      data: {
        email: 'override@rbac.test.local',
        passwordHash: 'not-a-real-hash',
        firstName: 'Over',
        lastName: 'Rider',
      },
    });
    await prisma.userPermissionOverride.create({
      data: { userId: user.id, permissionId: created.id, effect: 'DENY' },
    });

    await expect(service.remove(created.id, actorId, META)).rejects.toBeInstanceOf(
      ConflictException,
    );
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(service.remove('missing-id', actorId, META)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});
