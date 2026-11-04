import {
  Body,
  Controller,
  Delete,
  Get,
  HttpCode,
  Param,
  Patch,
  Post,
  Put,
  Req,
} from '@nestjs/common';
import type { Request } from 'express';
import { ApiBody, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../../../common/decorators/current-user.decorator.js';
import { RequirePermissions } from '../../../common/decorators/require-permissions.decorator.js';
import { requestMeta } from '../../../common/http/request-meta.js';
import { ZodValidationPipe } from '../../../common/pipes/zod-validation.pipe.js';
import { zodBody } from '../../../config/openapi.js';
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

@ApiTags('roles')
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
  @ApiBody(zodBody(createRoleSchema))
  @Post()
  @HttpCode(201)
  create(
    @Body(new ZodValidationPipe(createRoleSchema)) dto: CreateRoleDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<RoleView> {
    return this.roles.create(dto, actorId, requestMeta(req));
  }

  @RequirePermissions('roles.update')
  @ApiBody(zodBody(updateRoleSchema))
  @Patch(':id')
  update(
    @Param('id', new ZodValidationPipe(roleIdSchema)) id: string,
    @Body(new ZodValidationPipe(updateRoleSchema)) dto: UpdateRoleDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<RoleView> {
    return this.roles.update(id, dto, actorId, requestMeta(req));
  }

  @RequirePermissions('roles.update')
  @ApiBody(zodBody(setRolePermissionsSchema))
  @Put(':id/permissions')
  @HttpCode(200)
  setPermissions(
    @Param('id', new ZodValidationPipe(roleIdSchema)) id: string,
    @Body(new ZodValidationPipe(setRolePermissionsSchema)) dto: SetRolePermissionsDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<RoleView> {
    return this.roles.setPermissions(id, dto.permissionKeys, actorId, requestMeta(req));
  }

  @RequirePermissions('roles.delete')
  @Delete(':id')
  @HttpCode(204)
  async remove(
    @Param('id', new ZodValidationPipe(roleIdSchema)) id: string,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<void> {
    await this.roles.remove(id, actorId, requestMeta(req));
  }
}
