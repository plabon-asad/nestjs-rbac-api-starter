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
import { UsersService } from '../services/users.service.js';
import {
  assignRolesSchema,
  createUserSchema,
  updateUserSchema,
  userIdSchema,
  type AssignRolesDto,
  type CreateUserDto,
  type UpdateUserDto,
} from '../dto/user.schemas.js';
import type { UserAdminView } from '../models/user-views.js';

@ApiTags('users')
@Controller('users')
export class UsersController {
  constructor(private readonly users: UsersService) {}

  @RequirePermissions('users.read')
  @Get()
  list(): Promise<UserAdminView[]> {
    return this.users.list();
  }

  @RequirePermissions('users.read')
  @Get(':id')
  findOne(@Param('id', new ZodValidationPipe(userIdSchema)) id: string): Promise<UserAdminView> {
    return this.users.findById(id);
  }

  @RequirePermissions('users.create')
  @ApiBody(zodBody(createUserSchema))
  @Post()
  @HttpCode(201)
  create(
    @Body(new ZodValidationPipe(createUserSchema)) dto: CreateUserDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<UserAdminView> {
    return this.users.create(dto, actorId, requestMeta(req));
  }

  @RequirePermissions('users.update')
  @ApiBody(zodBody(updateUserSchema))
  @Patch(':id')
  update(
    @Param('id', new ZodValidationPipe(userIdSchema)) id: string,
    @Body(new ZodValidationPipe(updateUserSchema)) dto: UpdateUserDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<UserAdminView> {
    return this.users.update(id, dto, actorId, requestMeta(req));
  }

  @RequirePermissions('users.assign-roles')
  @ApiBody(zodBody(assignRolesSchema))
  @Put(':id/roles')
  @HttpCode(200)
  assignRoles(
    @Param('id', new ZodValidationPipe(userIdSchema)) id: string,
    @Body(new ZodValidationPipe(assignRolesSchema)) dto: AssignRolesDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<UserAdminView> {
    return this.users.assignRoles(id, dto.roleNames, actorId, requestMeta(req));
  }

  @RequirePermissions('users.delete')
  @Delete(':id')
  @HttpCode(204)
  async remove(
    @Param('id', new ZodValidationPipe(userIdSchema)) id: string,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<void> {
    await this.users.remove(id, actorId, requestMeta(req));
  }
}
