import { Body, Controller, Get, HttpCode, Param, Put, Req } from '@nestjs/common';
import type { Request } from 'express';
import { CurrentUser } from '../../../common/decorators/current-user.decorator.js';
import { RequirePermissions } from '../../../common/decorators/require-permissions.decorator.js';
import { requestMeta } from '../../../common/http/request-meta.js';
import { ZodValidationPipe } from '../../../common/pipes/zod-validation.pipe.js';
import {
  PermissionOverridesService,
  type PermissionOverrideView,
} from '../services/permission-overrides.service.js';
import {
  permissionKeySchema,
  setOverrideSchema,
  userIdSchema,
  type SetOverrideDto,
} from '../dto/override.schemas.js';

@Controller('permission-overrides')
export class PermissionOverridesController {
  constructor(private readonly overrides: PermissionOverridesService) {}

  @RequirePermissions('permission-overrides.read')
  @Get(':userId')
  list(
    @Param('userId', new ZodValidationPipe(userIdSchema)) userId: string,
  ): Promise<PermissionOverrideView[]> {
    return this.overrides.list(userId);
  }

  @RequirePermissions('permission-overrides.manage')
  @Put(':userId/:permissionKey')
  @HttpCode(200)
  set(
    @Param('userId', new ZodValidationPipe(userIdSchema)) userId: string,
    @Param('permissionKey', new ZodValidationPipe(permissionKeySchema)) permissionKey: string,
    @Body(new ZodValidationPipe(setOverrideSchema)) dto: SetOverrideDto,
    @CurrentUser('id') actorId: string,
    @Req() req: Request,
  ): Promise<PermissionOverrideView | null> {
    return this.overrides.set(userId, permissionKey, dto.effect, actorId, requestMeta(req));
  }
}
