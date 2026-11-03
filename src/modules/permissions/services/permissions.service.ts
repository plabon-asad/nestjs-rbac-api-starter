import {
  BadRequestException,
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { Prisma, type Permission } from '../../../generated/prisma/client.js';
import { isPermissionSlug } from '../../../database/seeds/rbac-catalogue.js';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import { isUniqueViolation } from '../../../common/prisma/unique-constraint.js';
import type { CreatePermissionDto, UpdatePermissionDto } from '../dto/permission.schemas.js';
import { toPermissionView, type PermissionView } from '../models/permission-views.js';

@Injectable()
export class PermissionsService {
  constructor(private readonly prisma: PrismaService) {}

  async list(): Promise<PermissionView[]> {
    const permissions = await this.prisma.permission.findMany({ orderBy: { key: 'asc' } });
    return permissions.map(toPermissionView);
  }

  async findById(id: string): Promise<PermissionView> {
    return toPermissionView(await this.requirePermission(id));
  }

  async create(dto: CreatePermissionDto): Promise<PermissionView> {
    if (!isPermissionSlug(dto.resource) || !isPermissionSlug(dto.action)) {
      throw new BadRequestException('resource and action must be lowercase slugs');
    }

    const key = `${dto.resource}.${dto.action}`;
    try {
      const permission = await this.prisma.permission.create({
        data: {
          key,
          name: dto.name,
          description: dto.description ?? null,
          resource: dto.resource,
          action: dto.action,
        },
      });
      return toPermissionView(permission);
    } catch (error) {
      if (isUniqueViolation(error)) {
        throw new ConflictException(`Permission ${key} already exists`);
      }
      throw error;
    }
  }

  async update(id: string, dto: UpdatePermissionDto): Promise<PermissionView> {
    await this.requirePermission(id);

    const data: Prisma.PermissionUpdateInput = {};
    if (dto.name !== undefined) data.name = dto.name;
    if (dto.description !== undefined) data.description = dto.description;

    const permission = await this.prisma.permission.update({ where: { id }, data });
    return toPermissionView(permission);
  }

  /**
   * Deleting a permission would cascade away the role grants and per-user overrides that
   * reference it, so in-use permissions are refused rather than silently unwired.
   */
  async remove(id: string): Promise<void> {
    await this.requirePermission(id);

    const [roleGrants, overrides] = await Promise.all([
      this.prisma.rolePermission.count({ where: { permissionId: id } }),
      this.prisma.userPermissionOverride.count({ where: { permissionId: id } }),
    ]);
    if (roleGrants > 0) {
      throw new ConflictException(
        `Permission is granted to ${roleGrants} role(s); revoke it from those roles first`,
      );
    }
    if (overrides > 0) {
      throw new ConflictException(
        `Permission has ${overrides} user override(s); reset those overrides first`,
      );
    }

    await this.prisma.permission.delete({ where: { id } });
  }

  private async requirePermission(id: string): Promise<Permission> {
    const permission = await this.prisma.permission.findUnique({ where: { id } });
    if (permission === null) {
      throw new NotFoundException(`Permission ${id} not found`);
    }
    return permission;
  }
}
