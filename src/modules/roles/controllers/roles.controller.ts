import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Put } from '@nestjs/common';
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

  @Get()
  list(): Promise<RoleView[]> {
    return this.roles.list();
  }

  @Get(':id')
  findOne(@Param('id', new ZodValidationPipe(roleIdSchema)) id: string): Promise<RoleView> {
    return this.roles.findById(id);
  }

  @Post()
  @HttpCode(201)
  create(@Body(new ZodValidationPipe(createRoleSchema)) dto: CreateRoleDto): Promise<RoleView> {
    return this.roles.create(dto);
  }

  @Patch(':id')
  update(
    @Param('id', new ZodValidationPipe(roleIdSchema)) id: string,
    @Body(new ZodValidationPipe(updateRoleSchema)) dto: UpdateRoleDto,
  ): Promise<RoleView> {
    return this.roles.update(id, dto);
  }

  @Put(':id/permissions')
  @HttpCode(200)
  setPermissions(
    @Param('id', new ZodValidationPipe(roleIdSchema)) id: string,
    @Body(new ZodValidationPipe(setRolePermissionsSchema)) dto: SetRolePermissionsDto,
  ): Promise<RoleView> {
    return this.roles.setPermissions(id, dto.permissionKeys);
  }

  @Delete(':id')
  @HttpCode(204)
  async remove(@Param('id', new ZodValidationPipe(roleIdSchema)) id: string): Promise<void> {
    await this.roles.remove(id);
  }
}
