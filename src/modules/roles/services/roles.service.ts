import {
  BadRequestException,
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import type { Prisma } from '../../../generated/prisma/client.js';
import type { RequestMeta } from '../../../common/interfaces/request-meta.interface.js';
import { isUniqueViolation } from '../../../common/prisma/unique-constraint.js';
import { AuditLogService } from '../../audit-logs/audit-log.service.js';
import { PermissionEvaluatorService } from '../../authz/services/permission-evaluator.service.js';
import type { CreateRoleDto, UpdateRoleDto } from '../dto/role.schemas.js';
import { roleWithPermissions, toRoleView, type RoleView } from '../models/role-views.js';

@Injectable()
export class RolesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly evaluator: PermissionEvaluatorService,
    private readonly audit: AuditLogService,
  ) {}

  async list(): Promise<RoleView[]> {
    const roles = await this.prisma.role.findMany({
      include: roleWithPermissions,
      orderBy: { name: 'asc' },
    });
    return roles.map(toRoleView);
  }

  async findById(id: string): Promise<RoleView> {
    return toRoleView(await this.requireRole(id));
  }

  async create(dto: CreateRoleDto, actorId: string, meta: RequestMeta): Promise<RoleView> {
    const permissionKeys = dto.permissionKeys ?? [];
    // Grant-scope: creating a role that carries a permission you do not hold is escalation.
    await this.evaluator.assertCanGrant(actorId, permissionKeys);

    const permissionIds = await this.resolvePermissionIds(permissionKeys);

    try {
      const role = await this.prisma.$transaction(async (tx) => {
        const created = await tx.role.create({
          data: { name: dto.name, description: dto.description ?? null },
        });
        if (permissionIds.length > 0) {
          await tx.rolePermission.createMany({
            data: permissionIds.map((permissionId) => ({
              roleId: created.id,
              permissionId,
            })),
          });
        }
        return created;
      });

      await this.audit.record({
        actorUserId: actorId,
        action: 'role.created',
        resourceType: 'role',
        resourceId: role.id,
        changes: { name: dto.name, permissionKeys },
        meta,
      });

      return await this.findById(role.id);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ConflictException(`Role ${dto.name} already exists`);
      }
      throw error;
    }
  }

  async update(
    id: string,
    dto: UpdateRoleDto,
    actorId: string,
    meta: RequestMeta,
  ): Promise<RoleView> {
    const role = await this.requireRole(id);
    this.assertMutable(role.isSystem, 'rename');

    const data: Prisma.RoleUpdateInput = {};
    if (dto.name !== undefined) data.name = dto.name;
    if (dto.description !== undefined) data.description = dto.description;

    try {
      await this.prisma.role.update({ where: { id }, data });
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ConflictException(`Role ${dto.name} already exists`);
      }
      throw error;
    }

    await this.audit.record({
      actorUserId: actorId,
      action: 'role.updated',
      resourceType: 'role',
      resourceId: id,
      changes: { ...dto },
      meta,
    });

    return await this.findById(id);
  }

  /** Replace semantics: the role ends up holding exactly the supplied keys. */
  async setPermissions(
    id: string,
    permissionKeys: readonly string[],
    actorId: string,
    meta: RequestMeta,
  ): Promise<RoleView> {
    const role = await this.requireRole(id);
    this.assertMutable(role.isSystem, 'revoke permissions from');
    await this.evaluator.assertCanGrant(actorId, permissionKeys);

    const permissionIds = await this.resolvePermissionIds(permissionKeys);
    await this.prisma.$transaction(async (tx) => {
      await tx.rolePermission.deleteMany({ where: { roleId: id } });
      if (permissionIds.length > 0) {
        await tx.rolePermission.createMany({
          data: permissionIds.map((permissionId) => ({ roleId: id, permissionId })),
        });
      }
    });

    await this.audit.record({
      actorUserId: actorId,
      action: 'role.grants_updated',
      resourceType: 'role',
      resourceId: id,
      changes: { permissionKeys },
      meta,
    });

    return await this.findById(id);
  }

  async remove(id: string, actorId: string, meta: RequestMeta): Promise<void> {
    const role = await this.requireRole(id);
    this.assertMutable(role.isSystem, 'delete');

    const members = await this.prisma.userRole.count({ where: { roleId: id } });
    if (members > 0) {
      throw new ConflictException(`Role is assigned to ${members} user(s); reassign them first`);
    }

    await this.prisma.role.delete({ where: { id } });
    await this.audit.record({
      actorUserId: actorId,
      action: 'role.deleted',
      resourceType: 'role',
      resourceId: id,
      changes: { name: role.name },
      meta,
    });
  }

  private assertMutable(isSystem: boolean, verb: string): void {
    if (isSystem) {
      throw new ForbiddenException(`The system role cannot be ${verb}`);
    }
  }

  private async requireRole(id: string) {
    const role = await this.prisma.role.findUnique({
      where: { id },
      include: roleWithPermissions,
    });
    if (role === null) {
      throw new NotFoundException(`Role ${id} not found`);
    }
    return role;
  }

  private async resolvePermissionIds(keys: readonly string[]): Promise<string[]> {
    const wanted = [...new Set(keys)];
    if (wanted.length === 0) return [];

    const found = await this.prisma.permission.findMany({
      where: { key: { in: wanted } },
      select: { id: true, key: true },
    });
    const known = new Set(found.map((permission) => permission.key));
    const unknown = wanted.filter((key) => !known.has(key));

    if (unknown.length > 0) {
      throw new BadRequestException(`Unknown permission keys: ${unknown.join(', ')}`);
    }
    return found.map((permission) => permission.id);
  }
}
