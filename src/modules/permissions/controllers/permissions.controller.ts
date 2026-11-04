import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post, Req } from '@nestjs/common';
import type { Request } from 'express';
import { ApiBody, ApiTags } from '@nestjs/swagger';
import { CurrentUser } from '../../../common/decorators/current-user.decorator.js';
import { RequirePermissions } from '../../../common/decorators/require-permissions.decorator.js';
import { requestMeta } from '../../../common/http/request-meta.js';
import { ZodValidationPipe } from '../../../common/pipes/zod-validation.pipe.js';
import { zodBody } from '../../../config/openapi.js';
import { PermissionsService } from '../services/permissions.service.js';
import {
  createPermissionSchema,
  permissionIdSchema,
  updatePermissionSchema,
  type CreatePermissionDto,
  type UpdatePermissionDto,
} from '../dto/permission.schemas.js';
import type { PermissionView } from '../models/permission-views.js';

@ApiTags('permissions')
@Controller('permissions')
export class PermissionsController {
  constructor(private readonly permissions: PermissionsService) {}

  @RequirePermissions('permissions.read')
  @Get()
  list(): Promise<PermissionView[]> {
    return this.permissions.list();
  }

  @RequirePermissions('permissions.read')
  @Get(':id')
  findOne(
    @Param('id', new ZodValidationPipe(permissionIdSchema)) id: string,
  ): Promise<PermissionView> {
    return this.permissions.findById(id);
  }

  @RequirePermissions('permissions.create')
  @ApiBody(zodBody(createPermissionSchema))
  @Post()
  @HttpCode(201)
  create(
    @Body(new ZodValidationPipe(createPermissionSchema)) dto: CreatePermissionDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<PermissionView> {
    return this.permissions.create(dto, actorId, requestMeta(req));
  }

  @RequirePermissions('permissions.update')
  @ApiBody(zodBody(updatePermissionSchema))
  @Patch(':id')
  update(
    @Param('id', new ZodValidationPipe(permissionIdSchema)) id: string,
    @Body(new ZodValidationPipe(updatePermissionSchema)) dto: UpdatePermissionDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<PermissionView> {
    return this.permissions.update(id, dto, actorId, requestMeta(req));
  }

  @RequirePermissions('permissions.delete')
  @Delete(':id')
  @HttpCode(204)
  async remove(
    @Param('id', new ZodValidationPipe(permissionIdSchema)) id: string,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<void> {
    await this.permissions.remove(id, actorId, requestMeta(req));
  }
}
