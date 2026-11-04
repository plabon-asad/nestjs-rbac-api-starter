import { beforeEach, describe, expect, it } from 'vitest';
import { ForbiddenException } from '@nestjs/common';
import { PermissionEvaluatorService } from '../../src/modules/authz/services/permission-evaluator.service.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import { createUserFixture } from '../utils/rbac-fixtures.js';

const evaluator = new PermissionEvaluatorService(prisma);

beforeEach(async () => {
  await resetTestDatabase();
});

describe('PermissionEvaluatorService.factsFor', () => {
  it('returns null for an account that no longer exists', async () => {
    await expect(evaluator.factsFor('deleted-user-id')).resolves.toBeNull();
  });

  it('unions the permissions of every assigned role', async () => {
    const userId = await createUserFixture('union@rbac.test.local');
    await prisma.permission.createMany({
      data: [
        { key: 'roles.read', name: 'Read roles', resource: 'roles', action: 'read' },
        { key: 'users.read', name: 'Read users', resource: 'users', action: 'read' },
        { key: 'audit-logs.read', name: 'Read audit', resource: 'audit-logs', action: 'read' },
      ],
    });
    const reader = await prisma.role.create({ data: { name: 'READER' } });
    const auditor = await prisma.role.create({ data: { name: 'AUDITOR' } });
    await linkPermissions(reader.id, ['roles.read', 'users.read']);
    await linkPermissions(auditor.id, ['audit-logs.read']);
    await assignRoles(userId, [reader.id, auditor.id]);

    const facts = await evaluator.factsFor(userId);
    expect([...(facts?.permissions ?? [])].sort()).toEqual([
      'audit-logs.read',
      'roles.read',
      'users.read',
    ]);
    expect(facts?.superAdmin).toBe(false);
  });

  it('flags membership of a system role', async () => {
    const userId = await createUserFixture('root@rbac.test.local');
    const system = await prisma.role.create({ data: { name: 'SUPER_ADMIN', isSystem: true } });
    await assignRoles(userId, [system.id]);

    const facts = await evaluator.factsFor(userId);
    expect(facts?.superAdmin).toBe(true);
    expect(facts?.permissions.size).toBe(0);
  });
});

describe('PermissionEvaluatorService.isAllowed', () => {
  it('reflects a revocation on the next call, without any caching in between', async () => {
    const userId = await createUserFixture('revoke@rbac.test.local');
    await prisma.permission.create({
      data: { key: 'roles.delete', name: 'Delete roles', resource: 'roles', action: 'delete' },
    });
    const role = await prisma.role.create({ data: { name: 'MANAGER' } });
    await linkPermissions(role.id, ['roles.delete']);
    await assignRoles(userId, [role.id]);

    await expect(evaluator.isAllowed(userId, ['roles.delete'], 'and')).resolves.toBe(true);

    await prisma.rolePermission.deleteMany({ where: { roleId: role.id } });
    await expect(evaluator.isAllowed(userId, ['roles.delete'], 'and')).resolves.toBe(false);
  });

  it('reflects a role assignment on the next call', async () => {
    const userId = await createUserFixture('assign@rbac.test.local');
    await prisma.permission.create({
      data: { key: 'users.read', name: 'Read users', resource: 'users', action: 'read' },
    });
    const role = await prisma.role.create({ data: { name: 'STAFF' } });
    await linkPermissions(role.id, ['users.read']);

    await expect(evaluator.isAllowed(userId, ['users.read'], 'and')).resolves.toBe(false);
    await assignRoles(userId, [role.id]);
    await expect(evaluator.isAllowed(userId, ['users.read'], 'and')).resolves.toBe(true);

    await prisma.userRole.deleteMany({ where: { userId } });
    await expect(evaluator.isAllowed(userId, ['users.read'], 'and')).resolves.toBe(false);
  });

  it('denies a disabled account that still holds every grant', async () => {
    const userId = await createUserFixture('off@rbac.test.local', { status: 'DISABLED' });
    await prisma.permission.create({
      data: { key: 'users.read', name: 'Read users', resource: 'users', action: 'read' },
    });
    const role = await prisma.role.create({ data: { name: 'STAFF' } });
    await linkPermissions(role.id, ['users.read']);
    await assignRoles(userId, [role.id]);

    await expect(evaluator.isAllowed(userId, ['users.read'], 'or')).resolves.toBe(false);
  });

  it('allows a system-role holder anything, and still denies when deactivated', async () => {
    const userId = await createUserFixture('root2@rbac.test.local');
    const system = await prisma.role.create({ data: { name: 'SUPER_ADMIN', isSystem: true } });
    await assignRoles(userId, [system.id]);

    await expect(evaluator.isAllowed(userId, ['whatever.key'], 'and')).resolves.toBe(true);

    await prisma.user.update({ where: { id: userId }, data: { status: 'LOCKED' } });
    await expect(evaluator.isAllowed(userId, ['whatever.key'], 'and')).resolves.toBe(false);
  });

  it('never confuses one user with another', async () => {
    const alice = await createUserFixture('alice@rbac.test.local');
    const bob = await createUserFixture('bob@rbac.test.local');
    await prisma.permission.create({
      data: { key: 'users.read', name: 'Read users', resource: 'users', action: 'read' },
    });
    const role = await prisma.role.create({ data: { name: 'STAFF' } });
    await linkPermissions(role.id, ['users.read']);
    await assignRoles(alice, [role.id]);

    await expect(evaluator.isAllowed(alice, ['users.read'], 'and')).resolves.toBe(true);
    await expect(evaluator.isAllowed(bob, ['users.read'], 'and')).resolves.toBe(false);
  });
});

describe('PermissionEvaluatorService.assertAllowed', () => {
  it('throws ForbiddenException when the requirement is not met', async () => {
    const userId = await createUserFixture('deny@rbac.test.local');
    await expect(evaluator.assertAllowed(userId, ['users.read'], 'and')).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('resolves silently when it is met', async () => {
    const userId = await createUserFixture('grant@rbac.test.local');
    await prisma.permission.create({
      data: { key: 'users.read', name: 'Read users', resource: 'users', action: 'read' },
    });
    const role = await prisma.role.create({ data: { name: 'STAFF' } });
    await linkPermissions(role.id, ['users.read']);
    await assignRoles(userId, [role.id]);

    await expect(evaluator.assertAllowed(userId, ['users.read'], 'and')).resolves.toBeUndefined();
  });
});

async function linkPermissions(roleId: string, keys: readonly string[]): Promise<void> {
  const permissions = await prisma.permission.findMany({ where: { key: { in: [...keys] } } });
  await prisma.rolePermission.createMany({
    data: permissions.map((permission) => ({ roleId, permissionId: permission.id })),
  });
}

async function assignRoles(userId: string, roleIds: readonly string[]): Promise<void> {
  await prisma.userRole.createMany({ data: roleIds.map((roleId) => ({ userId, roleId })) });
}
