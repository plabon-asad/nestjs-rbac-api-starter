import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { AUTHENTICATED_ONLY_KEY } from '../../../common/decorators/authenticated-only.decorator.js';
import { IS_PUBLIC_KEY } from '../../../common/decorators/public.decorator.js';
import {
  REQUIRE_PERMISSIONS_KEY,
  type PermissionRequirement,
} from '../../../common/decorators/require-permissions.decorator.js';
import type { AuthenticatedUser } from '../../../common/interfaces/authenticated-user.interface.js';
import { PermissionEvaluatorService } from '../services/permission-evaluator.service.js';

@Injectable()
export class PermissionsGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly evaluator: PermissionEvaluatorService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const scope = [context.getHandler(), context.getClass()];

    if (this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, scope)) {
      return true;
    }
    if (this.reflector.getAllAndOverride<boolean>(AUTHENTICATED_ONLY_KEY, scope)) {
      return true;
    }

    const requirement = this.reflector.getAllAndOverride<PermissionRequirement | undefined>(
      REQUIRE_PERMISSIONS_KEY,
      scope,
    );
    if (requirement === undefined) {
      // RoutePolicyScanner refuses to boot in this state; kept as defence in depth.
      throw new ForbiddenException('Route declares no access policy');
    }

    const request = context.switchToHttp().getRequest<Request & { user?: AuthenticatedUser }>();
    const user = request.user;
    if (user === undefined) {
      throw new UnauthorizedException('Authentication required');
    }

    await this.evaluator.assertAllowed(user.id, requirement.keys, requirement.mode);
    return true;
  }
}
