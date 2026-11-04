import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import type { Prisma, User } from '../../../generated/prisma/client.js';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import { isUniqueViolation } from '../../../common/prisma/unique-constraint.js';
import type { RequestMeta } from '../../../common/interfaces/request-meta.interface.js';
import { AuditLogService } from '../../audit-logs/audit-log.service.js';
import { PasswordService } from '../../auth/services/password.service.js';
import { PermissionEvaluatorService } from '../../authz/services/permission-evaluator.service.js';
import type { CreateUserDto, UpdateUserDto } from '../dto/user.schemas.js';
import { toUserAdminView, type UserAdminView } from '../models/user-views.js';

const userWithRoles = {
  roles: { include: { role: { select: { name: true, isSystem: true } } } },
} satisfies Prisma.UserInclude;

type UserRow = User & { roles: { role: { name: string; isSystem: boolean } }[] };

interface RoleRecord {
  readonly id: string;
  readonly name: string;
  readonly isSystem: boolean;
  readonly permissionKeys: readonly string[];
}

@Injectable()
export class UsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly passwords: PasswordService,
    private readonly evaluator: PermissionEvaluatorService,
    private readonly audit: AuditLogService,
  ) {}

  async list(): Promise<UserAdminView[]> {
    const users = await this.prisma.user.findMany({
      include: userWithRoles,
      orderBy: { email: 'asc' },
    });
    return users.map(toUserAdminView);
  }

  async findById(id: string): Promise<UserAdminView> {
    return toUserAdminView(await this.requireUser(id));
  }

  async create(dto: CreateUserDto, actorId: string, meta: RequestMeta): Promise<UserAdminView> {
    const roleNames = dto.roleNames ?? [];
    const roles = await this.resolveRoles(roleNames);
    await this.assertCanAssign(actorId, roles);

    const passwordHash = await this.passwords.hash(dto.password);
    try {
      const user = await this.prisma.$transaction(async (tx) => {
        const created = await tx.user.create({
          data: {
            email: dto.email,
            passwordHash,
            firstName: dto.firstName,
            lastName: dto.lastName,
          },
        });
        if (roles.length > 0) {
          await tx.userRole.createMany({
            data: roles.map((role) => ({ userId: created.id, roleId: role.id })),
          });
        }
        return created;
      });

      await this.audit.record({
        actorUserId: actorId,
        action: 'user.created',
        resourceType: 'user',
        resourceId: user.id,
        changes: {
          email: user.email,
          firstName: user.firstName,
          lastName: user.lastName,
          roleNames,
        },
        meta,
      });
      return await this.findById(user.id);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ConflictException(`A user with email ${dto.email} already exists`);
      }
      throw error;
    }
  }

  async update(
    id: string,
    dto: UpdateUserDto,
    actorId: string,
    meta: RequestMeta,
  ): Promise<UserAdminView> {
    await this.requireUser(id);

    if (id === actorId && dto.status === 'DISABLED') {
      throw new BadRequestException('You cannot disable your own account');
    }

    const data: Prisma.UserUpdateInput = {};
    if (dto.firstName !== undefined) data.firstName = dto.firstName;
    if (dto.lastName !== undefined) data.lastName = dto.lastName;
    if (dto.status !== undefined) {
      data.status = dto.status;
      if (dto.status === 'ACTIVE') {
        // Reactivating is also how an admin clears a lockout; leaving stale failure state
        // behind would let the counter immediately re-lock the account.
        data.failedLoginCount = 0;
        data.lockedUntil = null;
      }
    }

    await this.prisma.user.update({ where: { id }, data });
    await this.audit.record({
      actorUserId: actorId,
      action: 'user.updated',
      resourceType: 'user',
      resourceId: id,
      changes: { ...dto },
      meta,
    });
    return await this.findById(id);
  }

  /** Replace semantics: the user ends up holding exactly the supplied roles. */
  async assignRoles(
    id: string,
    roleNames: readonly string[],
    actorId: string,
    meta: RequestMeta,
  ): Promise<UserAdminView> {
    const target = await this.requireUser(id);
    const roles = await this.resolveRoles(roleNames);

    const targetIsSystem = target.roles.some((assignment) => assignment.role.isSystem);
    const actorIsSystem = await this.isSystemHolder(actorId);

    if (targetIsSystem && !actorIsSystem) {
      throw new ForbiddenException('Roles of a system-role holder can only be changed by a holder');
    }
    if (roles.some((role) => role.isSystem) && !actorIsSystem) {
      throw new ForbiddenException('Only a system-role holder can assign the system role');
    }

    const keepsSystem = roles.some((role) => role.isSystem);
    if (targetIsSystem && !keepsSystem) {
      await this.assertNotLastSystemHolder(target.id);
    }

    // Grant-scope only applies to additions: taking roles away is revocation, not granting.
    const current = new Set(target.roles.map((assignment) => assignment.role.name));
    const additions = roles.filter((role) => !current.has(role.name));
    if (additions.length > 0) {
      const keys = [...new Set(additions.flatMap((role) => role.permissionKeys))];
      await this.evaluator.assertCanGrant(actorId, keys);
    }

    await this.prisma.$transaction(async (tx) => {
      await tx.userRole.deleteMany({ where: { userId: id } });
      if (roles.length > 0) {
        await tx.userRole.createMany({
          data: roles.map((role) => ({ userId: id, roleId: role.id })),
        });
      }
    });

    await this.audit.record({
      actorUserId: actorId,
      action: 'user.roles_assigned',
      resourceType: 'user',
      resourceId: id,
      changes: { roleNames: [...roleNames] },
      meta,
    });
    return await this.findById(id);
  }

  async remove(id: string, actorId: string, meta: RequestMeta): Promise<void> {
    const target = await this.requireUser(id);

    if (id === actorId) {
      throw new BadRequestException('You cannot delete your own account');
    }
    const targetIsSystem = target.roles.some((assignment) => assignment.role.isSystem);
    if (targetIsSystem && !(await this.isSystemHolder(actorId))) {
      throw new ForbiddenException('A system-role holder can only be deleted by a holder');
    }

    await this.prisma.user.delete({ where: { id } });
    await this.audit.record({
      actorUserId: actorId,
      action: 'user.deleted',
      resourceType: 'user',
      resourceId: id,
      changes: { email: target.email },
      meta,
    });
  }

  private async requireUser(id: string): Promise<UserRow> {
    const user = await this.prisma.user.findUnique({ where: { id }, include: userWithRoles });
    if (user === null) {
      throw new NotFoundException(`User ${id} not found`);
    }
    return user;
  }

  private async isSystemHolder(userId: string): Promise<boolean> {
    const facts = await this.evaluator.factsFor(userId);
    return facts?.superAdmin === true;
  }

  private async assertCanAssign(actorId: string, roles: readonly RoleRecord[]): Promise<void> {
    if (roles.length === 0) return;

    if (roles.some((role) => role.isSystem) && !(await this.isSystemHolder(actorId))) {
      throw new ForbiddenException('Only a system-role holder can assign the system role');
    }
    const keys = [...new Set(roles.flatMap((role) => role.permissionKeys))];
    await this.evaluator.assertCanGrant(actorId, keys);
  }

  private async assertNotLastSystemHolder(targetId: string): Promise<void> {
    const others = await this.prisma.userRole.count({
      where: { userId: { not: targetId }, role: { isSystem: true } },
    });
    if (others === 0) {
      throw new ConflictException('The system role cannot be removed from its last holder');
    }
  }

  private async resolveRoles(names: readonly string[]): Promise<RoleRecord[]> {
    const wanted = [...new Set(names)];
    if (wanted.length === 0) return [];

    const found = await this.prisma.role.findMany({
      where: { name: { in: wanted } },
      select: {
        id: true,
        name: true,
        isSystem: true,
        permissions: { select: { permission: { select: { key: true } } } },
      },
    });
    const known = new Set(found.map((role) => role.name));
    const unknown = wanted.filter((name) => !known.has(name));
    if (unknown.length > 0) {
      throw new BadRequestException(`Unknown roles: ${unknown.join(', ')}`);
    }

    return found.map((role) => ({
      id: role.id,
      name: role.name,
      isSystem: role.isSystem,
      permissionKeys: role.permissions.map((grant) => grant.permission.key),
    }));
  }
}
