import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { Request } from 'express';
import { IS_PUBLIC_KEY } from '../../../common/decorators/public.decorator.js';
import type { AuthenticatedUser } from '../../../common/interfaces/authenticated-user.interface.js';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import { TokenService } from '../services/token.service.js';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(
    private readonly reflector: Reflector,
    private readonly tokens: TokenService,
    private readonly prisma: PrismaService,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

    const request = context.switchToHttp().getRequest<Request & { user?: AuthenticatedUser }>();
    const token = this.extractBearerToken(request);
    if (token === undefined) {
      throw new UnauthorizedException('Authentication required');
    }

    let claims;
    try {
      claims = await this.tokens.verifyAccessToken(token);
    } catch {
      throw new UnauthorizedException('Authentication required');
    }

    // Per-request server-side state: token alone never authorizes a stale session.
    const user = await this.prisma.user.findUnique({ where: { id: claims.sub } });
    if (user === null) {
      throw new UnauthorizedException('Authentication required');
    }
    if (user.status !== 'ACTIVE') {
      throw new ForbiddenException('Account is not active');
    }

    request.user = { id: user.id, sessionId: claims.sid };
    return true;
  }

  private extractBearerToken(request: Request): string | undefined {
    const header = request.headers.authorization;
    if (header !== undefined && header.startsWith('Bearer ')) {
      return header.slice('Bearer '.length);
    }
    return undefined;
  }
}
