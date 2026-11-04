import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
import { RequirePermissions } from '../../../common/decorators/require-permissions.decorator.js';
import { ZodValidationPipe } from '../../../common/pipes/zod-validation.pipe.js';
import { PermissionsService } from '../services/permissions.service.js';
import {
  createPermissionSchema,
  permissionIdSchema,
  updatePermissionSchema,
  type CreatePermissionDto,
  type UpdatePermissionDto,
} from '../dto/permission.schemas.js';
import type { PermissionView } from '../models/permission-views.js';

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
  @Post()
  @HttpCode(201)
  create(
    @Body(new ZodValidationPipe(createPermissionSchema)) dto: CreatePermissionDto,
  ): Promise<PermissionView> {
    return this.permissions.create(dto);
  }

  @RequirePermissions('permissions.update')
  @Patch(':id')
  update(
    @Param('id', new ZodValidationPipe(permissionIdSchema)) id: string,
    @Body(new ZodValidationPipe(updatePermissionSchema)) dto: UpdatePermissionDto,
  ): Promise<PermissionView> {
    return this.permissions.update(id, dto);
  }

  @RequirePermissions('permissions.delete')
  @Delete(':id')
  @HttpCode(204)
  async remove(@Param('id', new ZodValidationPipe(permissionIdSchema)) id: string): Promise<void> {
    await this.permissions.remove(id);
  }
}
