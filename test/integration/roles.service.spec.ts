import { afterAll, beforeEach, describe, expect, it } from 'vitest';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { RolesService } from '../../src/modules/roles/services/roles.service.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';

const service = new RolesService(prisma);
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

beforeEach(async () => {
  await resetTestDatabase();
  const catalogue = await seedCatalogue();
  readKey = catalogue.readKey;
  writeKey = catalogue.writeKey;
});

describe('RolesService.create', () => {
  it('creates a non-system role with the requested grants', async () => {
    const role = await service.create({
      name: 'Editor',
      description: 'Can edit documents',
      permissionKeys: [readKey, writeKey],
    });

    expect(role).toMatchObject({
      name: 'Editor',
      isSystem: false,
      description: 'Can edit documents',
    });
    expect([...role.permissionKeys].sort()).toEqual([readKey, writeKey].sort());
  });

  it('rejects a duplicate role name', async () => {
    await service.create({ name: 'Editor', permissionKeys: [] });

    await expect(service.create({ name: 'Editor', permissionKeys: [] })).rejects.toBeInstanceOf(
      ConflictException,
    );
  });

  it('rejects unknown permission keys instead of silently dropping them', async () => {
    await expect(
      service.create({ name: 'Ghost', permissionKeys: ['docs.does-not-exist'] }),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(prisma.role.findUnique({ where: { name: 'Ghost' } })).resolves.toBeNull();
  });

  it('cannot create a system role through the API surface', async () => {
    const role = await service.create({ name: 'Pseudo', permissionKeys: [] });
    expect(role.isSystem).toBe(false);
    await expect(
      prisma.role.findFirst({ where: { isSystem: true, id: role.id } }),
    ).resolves.toBeNull();
  });
});

describe('RolesService reads', () => {
  it('lists roles with their granted keys', async () => {
    await service.create({ name: 'Viewer', permissionKeys: [readKey] });
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
    const created = await service.create({ name: 'Viewer', permissionKeys: [readKey] });
    const updated = await service.update(created.id, { name: 'Reader' });

    expect(updated.name).toBe('Reader');
    expect(updated.permissionKeys).toEqual([readKey]);
  });

  it('refuses to rename or delete the protected system role', async () => {
    const system = await prisma.role.create({ data: { name: 'SUPER_ADMIN', isSystem: true } });

    await expect(service.update(system.id, { name: 'Not-Admin' })).rejects.toBeInstanceOf(
      ForbiddenException,
    );
    await expect(service.remove(system.id)).rejects.toBeInstanceOf(ForbiddenException);

    const stillThere = await prisma.role.findUnique({ where: { id: system.id } });
    expect(stillThere?.name).toBe('SUPER_ADMIN');
  });

  it('refuses to rename into an existing role name', async () => {
    await service.create({ name: 'Alpha', permissionKeys: [] });
    const beta = await service.create({ name: 'Beta', permissionKeys: [] });

    await expect(service.update(beta.id, { name: 'Alpha' })).rejects.toBeInstanceOf(
      ConflictException,
    );
  });
});

describe('RolesService.setPermissions', () => {
  it('replaces the whole grant set', async () => {
    const role = await service.create({ name: 'Writer', permissionKeys: [readKey] });
    const updated = await service.setPermissions(role.id, [writeKey]);

    expect(updated.permissionKeys).toEqual([writeKey]);
    await expect(prisma.rolePermission.count({ where: { roleId: role.id } })).resolves.toBe(1);
  });

  it('removes every grant when given an empty set', async () => {
    const role = await service.create({ name: 'Writer', permissionKeys: [readKey, writeKey] });
    const updated = await service.setPermissions(role.id, []);

    expect(updated.permissionKeys).toEqual([]);
    await expect(prisma.rolePermission.count({ where: { roleId: role.id } })).resolves.toBe(0);
  });

  it('refuses to mutate grants on the system role', async () => {
    const system = await prisma.role.create({ data: { name: 'SUPER_ADMIN', isSystem: true } });

    await expect(service.setPermissions(system.id, [readKey])).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('rejects unknown permission keys', async () => {
    const role = await service.create({ name: 'Writer', permissionKeys: [readKey] });

    await expect(service.setPermissions(role.id, ['nope.nope'])).rejects.toBeInstanceOf(
      BadRequestException,
    );
    const unchanged = await service.findById(role.id);
    expect(unchanged.permissionKeys).toEqual([readKey]);
  });

  it('throws NotFound for an unknown role', async () => {
    await expect(service.setPermissions('missing-role-id', [])).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('RolesService.remove', () => {
  it('deletes an unused role together with its grants', async () => {
    const role = await service.create({ name: 'Temporary', permissionKeys: [readKey] });
    await service.remove(role.id);

    await expect(prisma.role.findUnique({ where: { id: role.id } })).resolves.toBeNull();
    await expect(prisma.rolePermission.count({ where: { roleId: role.id } })).resolves.toBe(0);
  });

  it('refuses to delete a role that still has members', async () => {
    const role = await service.create({ name: 'Staff', permissionKeys: [] });
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
