import { Body, Controller, Delete, Get, HttpCode, Param, Patch, Post } from '@nestjs/common';
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

  @Get()
  list(): Promise<PermissionView[]> {
    return this.permissions.list();
  }

  @Get(':id')
  findOne(
    @Param('id', new ZodValidationPipe(permissionIdSchema)) id: string,
  ): Promise<PermissionView> {
    return this.permissions.findById(id);
  }

  @Post()
  @HttpCode(201)
  create(
    @Body(new ZodValidationPipe(createPermissionSchema)) dto: CreatePermissionDto,
  ): Promise<PermissionView> {
    return this.permissions.create(dto);
  }

  @Patch(':id')
  update(
    @Param('id', new ZodValidationPipe(permissionIdSchema)) id: string,
    @Body(new ZodValidationPipe(updatePermissionSchema)) dto: UpdatePermissionDto,
  ): Promise<PermissionView> {
    return this.permissions.update(id, dto);
  }

  @Delete(':id')
  @HttpCode(204)
  async remove(@Param('id', new ZodValidationPipe(permissionIdSchema)) id: string): Promise<void> {
    await this.permissions.remove(id);
  }
}
