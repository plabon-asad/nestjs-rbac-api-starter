import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import type { OverrideEffect } from '../../../generated/prisma/client.js';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import { PermissionEvaluatorService } from '../../authz/services/permission-evaluator.service.js';
import type { OverrideEffectInput } from '../dto/override.schemas.js';

export interface PermissionOverrideView {
  readonly permissionKey: string;
  readonly effect: OverrideEffect;
}

@Injectable()
export class PermissionOverridesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly evaluator: PermissionEvaluatorService,
  ) {}

  async list(userId: string): Promise<PermissionOverrideView[]> {
    await this.requireUser(userId);
    const rows = await this.prisma.userPermissionOverride.findMany({
      where: { userId },
      select: { effect: true, permission: { select: { key: true } } },
      orderBy: { permission: { key: 'asc' } },
    });
    return rows.map((row) => ({ permissionKey: row.permission.key, effect: row.effect }));
  }

  /**
   * INHERIT removes the row rather than storing an "inherit" value, so the result is always
   * derived from the live role grants. ALLOW is capped by the grant-scope rule: an actor can
   * only hand out permissions they effectively hold themselves.
   */
  async set(
    userId: string,
    permissionKey: string,
    effect: OverrideEffectInput,
    actorId: string,
  ): Promise<PermissionOverrideView | null> {
    await this.requireUser(userId);
    const permission = await this.prisma.permission.findUnique({
      where: { key: permissionKey },
      select: { id: true, key: true },
    });
    if (permission === null) {
      throw new BadRequestException(`Permission ${permissionKey} does not exist`);
    }
    await this.assertNotSystemMember(userId);

    if (effect === 'ALLOW') {
      await this.evaluator.assertAllowed(actorId, [permissionKey], 'and');
    }

    if (effect === 'INHERIT') {
      await this.prisma.userPermissionOverride.deleteMany({
        where: { userId, permissionId: permission.id },
      });
      return null;
    }

    await this.prisma.userPermissionOverride.upsert({
      where: { userId_permissionId: { userId, permissionId: permission.id } },
      create: { userId, permissionId: permission.id, effect },
      update: { effect },
    });
    return { permissionKey: permission.key, effect };
  }

  private async requireUser(userId: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId }, select: { id: true } });
    if (user === null) {
      throw new NotFoundException('User not found');
    }
  }

  /**
   * Overrides never apply to a system-role holder: the evaluation engine lets the system role
   * through before overrides are consulted, so a stored DENY would be a silent lie about access.
   */
  private async assertNotSystemMember(userId: string): Promise<void> {
    const systemMembership = await this.prisma.userRole.findFirst({
      where: { userId, role: { isSystem: true } },
      select: { userId: true },
    });
    if (systemMembership !== null) {
      throw new ForbiddenException('Permissions of a system-role holder cannot be overridden');
    }
  }
}
