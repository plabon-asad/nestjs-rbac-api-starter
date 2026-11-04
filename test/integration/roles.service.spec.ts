import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { PermissionEvaluatorService } from '../../src/modules/authz/services/permission-evaluator.service.js';
import { RolesService } from '../../src/modules/roles/services/roles.service.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import { createRoleFixture, createUserFixture, grantRole } from '../utils/rbac-fixtures.js';

const service = new RolesService(prisma, new PermissionEvaluatorService(prisma));
const passwords = new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });

async function seedCatalogue(): Promise<{ readKey: string; writeKey: string }> {
  const [read, write] = await Promise.all([
    prisma.permission.create({
      data: { key: 'docs.read', name: 'Read docs', resource: 'docs', action: 'read' },
    }),
    prisma.permission.create({
      data: { key: 'docs.write', name: 'Write docs', resource: 'docs', action: 'write' },
    }),
  ]);
  return { readKey: read.key, writeKey: write.key };
}

async function createMemberUser(email: string): Promise<string> {
  const user = await prisma.user.create({
    data: {
      email,
      passwordHash: await passwords.hash('member-password-123456'),
      firstName: 'Member',
      lastName: 'User',
    },
  });
  return user.id;
}

let readKey: string;
let writeKey: string;
/** Holds everything, through the system role. */
let adminId: string;
/** Holds docs.read only — proves grant-scope is enforced. */
let limitedId: string;

beforeEach(async () => {
  await resetTestDatabase();
  const catalogue = await seedCatalogue();
  readKey = catalogue.readKey;
  writeKey = catalogue.writeKey;

  await createRoleFixture('SUPER_ADMIN', [], true);
  adminId = await createUserFixture('admin@roles.test.local');
  await grantRole(adminId, 'SUPER_ADMIN');

  await createRoleFixture('DOC_READER', [readKey]);
  limitedId = await createUserFixture('limited@roles.test.local');
  await grantRole(limitedId, 'DOC_READER');
});

describe('RolesService.create', () => {
  it('creates a non-system role with the requested grants', async () => {
    const role = await service.create(
      { name: 'Editor', description: 'Can edit documents', permissionKeys: [readKey, writeKey] },
      adminId,
    );

    expect(role).toMatchObject({
      name: 'Editor',
      isSystem: false,
      description: 'Can edit documents',
    });
    expect([...role.permissionKeys].sort()).toEqual([readKey, writeKey].sort());
  });

  it('rejects a duplicate role name', async () => {
    await service.create({ name: 'Editor', permissionKeys: [] }, adminId);

    await expect(
      service.create({ name: 'Editor', permissionKeys: [] }, adminId),
    ).rejects.toBeInstanceOf(ConflictException);
  });

  it('rejects unknown permission keys instead of silently dropping them', async () => {
    await expect(
      service.create({ name: 'Ghost', permissionKeys: ['docs.does-not-exist'] }, adminId),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(prisma.role.findUnique({ where: { name: 'Ghost' } })).resolves.toBeNull();
  });

  it('refuses to grant permissions the actor does not hold', async () => {
    await expect(
      service.create({ name: 'Privileged', permissionKeys: [writeKey] }, limitedId),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(prisma.role.findUnique({ where: { name: 'Privileged' } })).resolves.toBeNull();
  });

  it('cannot create a system role through the API surface', async () => {
    const role = await service.create({ name: 'Pseudo', permissionKeys: [] }, adminId);

    expect(role.isSystem).toBe(false);
    await expect(
      prisma.role.findFirst({ where: { isSystem: true, id: role.id } }),
    ).resolves.toBeNull();
  });
});

describe('RolesService reads', () => {
  it('lists roles with their granted keys', async () => {
    await service.create({ name: 'Viewer', permissionKeys: [readKey] }, adminId);
    const roles = await service.list();

    expect(roles.map((role) => role.name)).toContain('Viewer');
    expect(roles.find((role) => role.name === 'Viewer')?.permissionKeys).toEqual([readKey]);
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(service.findById('missing-role-id')).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('RolesService.update', () => {
  it('renames a role and keeps its grants', async () => {
    const created = await service.create({ name: 'Viewer', permissionKeys: [readKey] }, adminId);
    const updated = await service.update(created.id, { name: 'Reader' });

    expect(updated.name).toBe('Reader');
    expect(updated.permissionKeys).toEqual([readKey]);
  });

  it('refuses to rename or delete the protected system role', async () => {
    const system = await prisma.role.findUniqueOrThrow({ where: { name: 'SUPER_ADMIN' } });

    await expect(service.update(system.id, { name: 'Not-Admin' })).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    await expect(service.remove(system.id)).rejects.toBeInstanceOf(ForbiddenException);

    const stillThere = await prisma.role.findUnique({ where: { id: system.id } });
    expect(stillThere?.name).toBe('SUPER_ADMIN');
  });

  it('refuses to rename into an existing role name', async () => {
    await service.create({ name: 'Alpha', permissionKeys: [] }, adminId);
    const beta = await service.create({ name: 'Beta', permissionKeys: [] }, adminId);

    await expect(service.update(beta.id, { name: 'Alpha' })).rejects.toBeInstanceOf(
      ConflictException,
    );
  });
});

describe('RolesService.setPermissions', () => {
  it('replaces the whole grant set', async () => {
    const role = await service.create({ name: 'Writer', permissionKeys: [readKey] }, adminId);
    const updated = await service.setPermissions(role.id, [writeKey], adminId);

    expect(updated.permissionKeys).toEqual([writeKey]);
    await expect(prisma.rolePermission.count({ where: { roleId: role.id } })).resolves.toBe(1);
  });

  it('removes every grant when given an empty set', async () => {
    const role = await service.create(
      { name: 'Writer', permissionKeys: [readKey, writeKey] },
      adminId,
    );
    const updated = await service.setPermissions(role.id, [], adminId);

    expect(updated.permissionKeys).toEqual([]);
    await expect(prisma.rolePermission.count({ where: { roleId: role.id } })).resolves.toBe(0);
  });

  it('refuses to mutate grants on the system role', async () => {
    const system = await prisma.role.findUniqueOrThrow({ where: { name: 'SUPER_ADMIN' } });

    await expect(service.setPermissions(system.id, [readKey], adminId)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('refuses to add a grant the actor does not hold, leaving the role untouched', async () => {
    const role = await service.create({ name: 'Writer', permissionKeys: [readKey] }, limitedId);

    await expect(service.setPermissions(role.id, [writeKey], limitedId)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    const unchanged = await service.findById(role.id);
    expect(unchanged.permissionKeys).toEqual([readKey]);
  });

  it('still allows an actor to revoke grants they do not hold', async () => {
    const role = await service.create({ name: 'Writer', permissionKeys: [writeKey] }, adminId);
    const updated = await service.setPermissions(role.id, [], limitedId);

    expect(updated.permissionKeys).toEqual([]);
  });

  it('rejects unknown permission keys', async () => {
    const role = await service.create({ name: 'Writer', permissionKeys: [readKey] }, adminId);

    await expect(service.setPermissions(role.id, ['nope.nope'], adminId)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    const unchanged = await service.findById(role.id);
    expect(unchanged.permissionKeys).toEqual([readKey]);
  });

  it('throws NotFound for an unknown role', async () => {
    await expect(service.setPermissions('missing-role-id', [], adminId)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('RolesService.remove', () => {
  it('deletes an unused role together with its grants', async () => {
    const role = await service.create({ name: 'Temporary', permissionKeys: [readKey] }, adminId);
    await service.remove(role.id);

    await expect(prisma.role.findUnique({ where: { id: role.id } })).resolves.toBeNull();
    await expect(prisma.rolePermission.count({ where: { roleId: role.id } })).resolves.toBe(0);
  });

  it('refuses to delete a role that still has members', async () => {
    const role = await service.create({ name: 'Staff', permissionKeys: [] }, adminId);
    const userId = await createMemberUser('member@rbac.test.local');
    await prisma.userRole.create({ data: { userId, roleId: role.id } });

    await expect(service.remove(role.id)).rejects.toBeInstanceOf(ConflictException);
    await expect(prisma.role.findUnique({ where: { id: role.id } })).resolves.not.toBeNull();
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(service.remove('missing-role-id')).rejects.toBeInstanceOf(NotFoundException);
  });
});

afterAll(async () => {
  await prisma.$disconnect();
});
