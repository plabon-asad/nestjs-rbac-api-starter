import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Put } from '@nestjs/common';
import { CurrentUser } from '../../../common/decorators/current-user.decorator.js';
import { RequirePermissions } from '../../../common/decorators/require-permissions.decorator.js';
import { ZodValidationPipe } from '../../../common/pipes/zod-validation.pipe.js';
import { RolesService } from '../services/roles.service.js';
import {
  createRoleSchema,
  roleIdSchema,
  setRolePermissionsSchema,
  updateRoleSchema,
  type CreateRoleDto,
  type SetRolePermissionsDto,
  type UpdateRoleDto,
} from '../dto/role.schemas.js';
import type { RoleView } from '../models/role-views.js';

@Controller('roles')
export class RolesController {
  constructor(private readonly roles: RolesService) {}

  @RequirePermissions('roles.read')
  @Get()
  list(): Promise<RoleView[]> {
    return this.roles.list();
  }

  @RequirePermissions('roles.read')
  @Get(':id')
  findOne(@Param('id', new ZodValidationPipe(roleIdSchema)) id: string): Promise<RoleView> {
    return this.roles.findById(id);
  }

  @RequirePermissions('roles.create')
  @Post()
  @HttpCode(201)
  create(
    @Body(new ZodValidationPipe(createRoleSchema)) dto: CreateRoleDto,
    @CurrentUser('id') actorId: string,
  ): Promise<RoleView> {
    return this.roles.create(dto, actorId);
  }

  @RequirePermissions('roles.update')
  @Patch(':id')
  update(
    @Param('id', new ZodValidationPipe(roleIdSchema)) id: string,
    @Body(new ZodValidationPipe(updateRoleSchema)) dto: UpdateRoleDto,
  ): Promise<RoleView> {
    return this.roles.update(id, dto);
  }

  @RequirePermissions('roles.update')
  @Put(':id/permissions')
  @HttpCode(200)
  setPermissions(
    @Param('id', new ZodValidationPipe(roleIdSchema)) id: string,
    @Body(new ZodValidationPipe(setRolePermissionsSchema)) dto: SetRolePermissionsDto,
    @CurrentUser('id') actorId: string,
  ): Promise<RoleView> {
    return this.roles.setPermissions(id, dto.permissionKeys, actorId);
  }

  @RequirePermissions('roles.delete')
  @Delete(':id')
  @HttpCode(204)
  async remove(@Param('id', new ZodValidationPipe(roleIdSchema)) id: string): Promise<void> {
    await this.roles.remove(id);
  }
}
