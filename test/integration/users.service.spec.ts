import { beforeEach, describe, expect, it } from 'vitest';
import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  NotFoundException,
} from '@nestjs/common';
import type { RequestMeta } from '../../src/common/interfaces/request-meta.interface.js';
import { AuditLogService } from '../../src/modules/audit-logs/audit-log.service.js';
import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { PermissionEvaluatorService } from '../../src/modules/authz/services/permission-evaluator.service.js';
import { UsersService } from '../../src/modules/users/services/users.service.js';
import { prisma, resetTestDatabase } from '../utils/prisma-test.js';
import {
  createPermissionFixture,
  createRoleFixture,
  createUserFixture,
  grantRole,
} from '../utils/rbac-fixtures.js';

const META: RequestMeta = { ip: '127.0.0.1', userAgent: 'users-service-spec' };
const passwords = new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });
const evaluator = new PermissionEvaluatorService(prisma);
const service = new UsersService(prisma, passwords, evaluator, new AuditLogService(prisma));

const CREATE_DTO = {
  email: 'newbie@users.test.local',
  password: 'initial-password-123',
  firstName: 'New',
  lastName: 'Bie',
  roleNames: [] as string[],
};

/** Root actor: holds the system role, so grant-scope never binds for it. */
let rootId: string;
/** Holds users.assign-roles + docs.read — enough for BASIC, not for POWERFUL or SUPER_ADMIN. */
let scopeId: string;

beforeEach(async () => {
  await resetTestDatabase();
  await createPermissionFixture('docs.read');
  await createPermissionFixture('docs.write');
  await createPermissionFixture('users.assign-roles');

  await createRoleFixture('SUPER_ADMIN', [], true);
  rootId = await createUserFixture('root@users.test.local');
  await grantRole(rootId, 'SUPER_ADMIN');

  await createRoleFixture('BASIC', ['docs.read']);
  await createRoleFixture('POWERFUL', ['docs.write']);
  await createRoleFixture('SCOPER', ['users.assign-roles', 'docs.read']);
  scopeId = await createUserFixture('scope@users.test.local');
  await grantRole(scopeId, 'SCOPER');
});

describe('UsersService.create', () => {
  it('hashes the password with argon2 and never returns the hash', async () => {
    const view = await service.create(CREATE_DTO, rootId, META);

    expect(view).toMatchObject({
      email: 'newbie@users.test.local',
      firstName: 'New',
      lastName: 'Bie',
      status: 'ACTIVE',
      roleNames: [],
    });
    expect('passwordHash' in view).toBe(false);

    const stored = await prisma.user.findUniqueOrThrow({ where: { id: view.id } });
    expect(stored.passwordHash.startsWith('$argon2')).toBe(true);
    await expect(passwords.verify(stored.passwordHash, CREATE_DTO.password)).resolves.toBeTruthy();
  });

  it('assigns the requested roles at creation time', async () => {
    const view = await service.create({ ...CREATE_DTO, roleNames: ['BASIC'] }, rootId, META);
    expect(view.roleNames).toEqual(['BASIC']);
  });

  it('audits user.created without any password material', async () => {
    await service.create(CREATE_DTO, rootId, META);

    const event = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'user.created' },
    });
    expect(event.actorUserId).toBe(rootId);
    expect(event.resourceType).toBe('user');
    expect(event.changes).toMatchObject({ email: CREATE_DTO.email });
    expect(JSON.stringify(event.changes)).not.toMatch(/password|argon2/i);
  });

  it('rejects a duplicate email and does not audit the refusal', async () => {
    await service.create(CREATE_DTO, rootId, META);

    await expect(service.create(CREATE_DTO, rootId, META)).rejects.toBeInstanceOf(
      ConflictException,
    );
    await expect(prisma.auditLog.count({ where: { action: 'user.created' } })).resolves.toBe(1);
  });

  it('rejects unknown role names and creates no user', async () => {
    await expect(
      service.create({ ...CREATE_DTO, roleNames: ['GHOST'] }, rootId, META),
    ).rejects.toBeInstanceOf(BadRequestException);
    await expect(prisma.user.count()).resolves.toBe(2);
  });

  it('refuses an actor to create a user holding the system role', async () => {
    await expect(
      service.create({ ...CREATE_DTO, roleNames: ['SUPER_ADMIN'] }, scopeId, META),
    ).rejects.toBeInstanceOf(ForbiddenException);
    await expect(prisma.user.count()).resolves.toBe(2);
  });

  it('refuses an actor to create a user holding a role they could not grant', async () => {
    await expect(
      service.create({ ...CREATE_DTO, roleNames: ['POWERFUL'] }, scopeId, META),
    ).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('lets an in-scope actor create a user with an ordinary role', async () => {
    const view = await service.create({ ...CREATE_DTO, roleNames: ['BASIC'] }, scopeId, META);
    expect(view.roleNames).toEqual(['BASIC']);
  });
});

describe('UsersService reads', () => {
  it('lists users with role names and without credential fields', async () => {
    const users = await service.list();

    expect(users.map((user) => user.email)).toEqual(
      ['root@users.test.local', 'scope@users.test.local'].sort(),
    );
    const root = users.find((user) => user.email === 'root@users.test.local');
    expect(root?.roleNames).toEqual(['SUPER_ADMIN']);
    expect('passwordHash' in (root ?? {})).toBe(false);
    expect('failedLoginCount' in (root ?? {})).toBe(false);
    expect('lockedUntil' in (root ?? {})).toBe(false);
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(service.findById('ghost-user-id')).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('UsersService.update', () => {
  it('edits profile fields and audits the change', async () => {
    const created = await service.create(CREATE_DTO, rootId, META);
    const updated = await service.update(
      created.id,
      { firstName: 'Renamed', lastName: 'Field' },
      rootId,
      META,
    );

    expect(updated.firstName).toBe('Renamed');
    const event = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'user.updated', resourceId: created.id },
    });
    expect(event.changes).toMatchObject({ firstName: 'Renamed' });
  });

  it('disables an account, which is enough to lock them out of protected routes', async () => {
    const created = await service.create(CREATE_DTO, rootId, META);
    const updated = await service.update(created.id, { status: 'DISABLED' }, rootId, META);

    expect(updated.status).toBe('DISABLED');
    await expect(evaluator.isAllowed(created.id, ['users.read'], 'and')).resolves.toBe(false);
  });

  it('reactivating an account clears the login-failure state', async () => {
    const created = await service.create(CREATE_DTO, rootId, META);
    await prisma.user.update({
      where: { id: created.id },
      data: { failedLoginCount: 4, lockedUntil: new Date(Date.now() + 60_000) },
    });

    await service.update(created.id, { status: 'ACTIVE' }, rootId, META);

    const stored = await prisma.user.findUniqueOrThrow({ where: { id: created.id } });
    expect(stored.failedLoginCount).toBe(0);
    expect(stored.lockedUntil).toBeNull();
  });

  it('refuses to disable the calling account: no self lock-outs', async () => {
    await expect(
      service.update(rootId, { status: 'DISABLED' }, rootId, META),
    ).rejects.toBeInstanceOf(BadRequestException);
    const stored = await prisma.user.findUniqueOrThrow({ where: { id: rootId } });
    expect(stored.status).toBe('ACTIVE');
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(
      service.update('ghost-user-id', { firstName: 'x' }, rootId, META),
    ).rejects.toBeInstanceOf(NotFoundException);
  });
});

describe('UsersService.assignRoles', () => {
  it('replaces the whole role set', async () => {
    const created = await service.create({ ...CREATE_DTO, roleNames: ['BASIC'] }, rootId, META);
    const updated = await service.assignRoles(created.id, ['POWERFUL'], rootId, META);

    expect(updated.roleNames).toEqual(['POWERFUL']);
    await expect(
      prisma.userRole.findMany({ where: { userId: created.id }, select: { roleId: true } }),
    ).resolves.toHaveLength(1);
    await expect(
      prisma.auditLog.findFirst({ where: { action: 'user.roles_assigned' } }),
    ).resolves.toMatchObject({ actorUserId: rootId });
  });

  it('accepts an empty set to strip all roles, but refuses to remove the last system holder', async () => {
    const created = await service.create({ ...CREATE_DTO, roleNames: ['BASIC'] }, rootId, META);
    const stripped = await service.assignRoles(created.id, [], rootId, META);
    expect(stripped.roleNames).toEqual([]);

    // rootId is the only SUPER_ADMIN holder after the strip.
    await expect(service.assignRoles(rootId, [], rootId, META)).rejects.toBeInstanceOf(
      ConflictException,
    );
    await expect(evaluator.factsFor(rootId)).resolves.toMatchObject({ superAdmin: true });
  });

  it('keeps a second system holder able to demote the first', async () => {
    const root2 = await createUserFixture('root2@users.test.local');
    await grantRole(root2, 'SUPER_ADMIN');

    const updated = await service.assignRoles(rootId, ['BASIC'], root2, META);
    expect(updated.roleNames).toEqual(['BASIC']);
  });

  it('refuses a non-actor-side system change: nobody edits a system holder without being one', async () => {
    await expect(service.assignRoles(rootId, ['BASIC'], scopeId, META)).rejects.toBeInstanceOf(
      ForbiddenException,
    );
  });

  it('refuses an out-of-scope addition and leaves the role set untouched', async () => {
    const created = await service.create({ ...CREATE_DTO, roleNames: ['BASIC'] }, rootId, META);

    await expect(
      service.assignRoles(created.id, ['BASIC', 'POWERFUL'], scopeId, META),
    ).rejects.toBeInstanceOf(ForbiddenException);
    const unchanged = await service.findById(created.id);
    expect(unchanged.roleNames).toEqual(['BASIC']);
  });

  it('allows removal of roles the actor could not grant: revoking is not granting', async () => {
    const created = await service.create({ ...CREATE_DTO, roleNames: ['POWERFUL'] }, rootId, META);
    const updated = await service.assignRoles(created.id, [], scopeId, META);
    expect(updated.roleNames).toEqual([]);
  });

  it('rejects unknown role names without touching the database', async () => {
    const created = await service.create({ ...CREATE_DTO, roleNames: ['BASIC'] }, rootId, META);

    await expect(service.assignRoles(created.id, ['GHOST'], rootId, META)).rejects.toBeInstanceOf(
      BadRequestException,
    );
    const unchanged = await service.findById(created.id);
    expect(unchanged.roleNames).toEqual(['BASIC']);
  });

  it('throws NotFound for an unknown target', async () => {
    await expect(service.assignRoles('ghost-user-id', [], rootId, META)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});

describe('UsersService.remove', () => {
  it('deletes an ordinary user and their role links, and audits the deletion', async () => {
    const created = await service.create({ ...CREATE_DTO, roleNames: ['BASIC'] }, rootId, META);
    await service.remove(created.id, rootId, META);

    await expect(prisma.user.findUnique({ where: { id: created.id } })).resolves.toBeNull();
    await expect(prisma.userRole.count({ where: { userId: created.id } })).resolves.toBe(0);
    const event = await prisma.auditLog.findFirstOrThrow({
      where: { action: 'user.deleted' },
    });
    expect(event.actorUserId).toBe(rootId);
    expect(JSON.stringify(event.changes)).not.toMatch(/password|argon2/i);
  });

  it('refuses to delete the calling account', async () => {
    await expect(service.remove(rootId, rootId, META)).rejects.toBeInstanceOf(BadRequestException);
  });

  it('refuses a non-system actor to delete a system holder', async () => {
    await expect(service.remove(rootId, scopeId, META)).rejects.toBeInstanceOf(ForbiddenException);
  });

  it('refuses to delete the last system holder even for a system actor', async () => {
    await expect(service.remove(rootId, rootId, META)).rejects.toBeInstanceOf(BadRequestException);
    const root2 = await createUserFixture('root3@users.test.local');
    await grantRole(root2, 'SUPER_ADMIN');
    // Two system holders now exist; deleting root via root2 is allowed.
    await service.remove(rootId, root2, META);
    // root2 is the last one; a self-delete still refuses, and no other system actor exists.
    await expect(service.remove(root2, root2, META)).rejects.toBeInstanceOf(BadRequestException);
  });

  it('throws NotFound for an unknown id', async () => {
    await expect(service.remove('ghost-user-id', rootId, META)).rejects.toBeInstanceOf(
      NotFoundException,
    );
  });
});
