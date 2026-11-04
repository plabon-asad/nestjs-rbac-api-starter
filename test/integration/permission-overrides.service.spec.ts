import { beforeEach, describe, expect, it } from 'vitest';
import { BadRequestException, ForbiddenException, NotFoundException } from '@nestjs/common';
import { PermissionEvaluatorService } from '../../src/modules/authz/services/permission-evaluator.service.js';
import { PermissionOverridesService } from '../../src/modules/permission-overrides/services/permission-overrides.service.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import {
  createPermissionFixture,
  createRoleFixture,
  createUserFixture,
  grantRole,
} from '../utils/rbac-fixtures.js';

const evaluator = new PermissionEvaluatorService(prisma);
const service = new PermissionOverridesService(prisma, evaluator);

async function actorWith(keys: readonly string[]): Promise<string> {
  const actorId = await createUserFixture(`actor@override.test.local`);
  if (keys.length > 0) {
    const roleName = `ACTOR_ROLE_${actorId}`;
    await createRoleFixture(roleName, keys);
    await grantRole(actorId, roleName);
  }
  return actorId;
}

beforeEach(async () => {
  await resetTestDatabase();
  await createPermissionFixture('users.read');
  await createPermissionFixture('users.delete');
  await createPermissionFixture('permission-overrides.manage');
});

describe('PermissionOverridesService.set', () => {
  it('stores ALLOW and DENY rows and reports them back', async () => {
    const userId = await createUserFixture('store@override.test.local');
    const actorId = await actorWith(['permission-overrides.manage', 'users.read', 'users.delete']);

    await expect(service.set(userId, 'users.read', 'ALLOW', actorId)).resolves.toMatchObject({
      permissionKey: 'users.read',
      effect: 'ALLOW',
    });
    await expect(service.set(userId, 'users.delete', 'DENY', actorId)).resolves.toMatchObject({
      permissionKey: 'users.delete',
      effect: 'DENY',
    });

    await expect(service.list(userId)).resolves.toEqual([
      { permissionKey: 'users.delete', effect: 'DENY' },
      { permissionKey: 'users.read', effect: 'ALLOW' },
    ]);
  });

  it('replacing an effect updates the single row per (user, permission)', async () => {
    const userId = await createUserFixture('switch@override.test.local');
    const actorId = await actorWith(['permission-overrides.manage', 'users.read']);

    await service.set(userId, 'users.read', 'DENY', actorId);
    await service.set(userId, 'users.read', 'ALLOW', actorId);

    await expect(prisma.userPermissionOverride.count({ where: { userId } })).resolves.toBe(1);
    await expect(service.list(userId)).resolves.toEqual([
      { permissionKey: 'users.read', effect: 'ALLOW' },
    ]);
  });

  it('INHERIT deletes the row and is idempotent when nothing is set', async () => {
    const userId = await createUserFixture('inherit@override.test.local');
    const actorId = await actorWith(['permission-overrides.manage']);

    await service.set(userId, 'users.read', 'DENY', actorId);
    await expect(service.set(userId, 'users.read', 'INHERIT', actorId)).resolves.toBeNull();
    await expect(service.list(userId)).resolves.toEqual([]);
    await expect(service.set(userId, 'users.read', 'INHERIT', actorId)).resolves.toBeNull();
  });

  it('refuses an unknown permission key with 400 and an unknown user with 404', async () => {
    const userId = await createUserFixture('validate@override.test.local');
    const actorId = await actorWith(['permission-overrides.manage']);

    await expect(service.set(userId, 'ghost.read', 'ALLOW', actorId)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    await expect(
      service.set('ghost-user-id', 'users.read', 'ALLOW', actorId),
    ).rejects.toBeInstanceOf(NotFoundException);
  });

  it('refuses ALLOW for a permission the actor does not effectively hold (grant-scope)', async () => {
    const userId = await createUserFixture('scope@override.test.local');
    const actorId = await actorWith(['permission-overrides.manage']);

    await expect(service.set(userId, 'users.delete', 'ALLOW', actorId)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    await expect(prisma.userPermissionOverride.count()).resolves.toBe(0);
  });

  it('allows DENY for a permission the actor does not hold: revoking is not granting', async () => {
    const userId = await createUserFixture('deny-only@override.test.local');
    const actorId = await actorWith(['permission-overrides.manage']);

    await expect(service.set(userId, 'users.delete', 'DENY', actorId)).resolves.toMatchObject({
      effect: 'DENY',
    });
  });

  it('lets a system-role holder ALLOW anything', async () => {
    const userId = await createUserFixture('by-root@override.test.local');
    await createRoleFixture('SUPER_ADMIN', [], true);
    const rootId = await createUserFixture('root@override.test.local');
    await grantRole(rootId, 'SUPER_ADMIN');

    await expect(service.set(userId, 'users.delete', 'ALLOW', rootId)).resolves.toMatchObject({
      effect: 'ALLOW',
    });
  });

  it('refuses every override on a target who holds the system role', async () => {
    await createRoleFixture('SUPER_ADMIN', [], true);
    const rootId = await createUserFixture('root-target@override.test.local');
    await grantRole(rootId, 'SUPER_ADMIN');
    const actorId = await actorWith(['permission-overrides.manage']);

    await expect(service.set(rootId, 'users.read', 'DENY', actorId)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    await expect(service.set(rootId, 'users.read', 'INHERIT', actorId)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('the written ALLOW takes effect for the target immediately', async () => {
    const userId = await createUserFixture('live@override.test.local');
    const actorId = await actorWith(['permission-overrides.manage', 'users.read']);

    await expect(evaluator.isAllowed(userId, ['users.read'], 'and')).resolves.toBe(false);
    await service.set(userId, 'users.read', 'ALLOW', actorId);
    await expect(evaluator.isAllowed(userId, ['users.read'], 'and')).resolves.toBe(true);
  });
});

describe('PermissionOverridesService.list', () => {
  it('throws 404 for an unknown account', async () => {
    await expect(service.list('ghost-user-id')).rejects.toBeInstanceOf(NotFoundException);
  });
});
