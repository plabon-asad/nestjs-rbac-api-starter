import { Injectable } from '@nestjs/common';
import type { Prisma } from '../../generated/prisma/client.js';
import { PrismaService } from '../../database/prisma/prisma.service.js';
import { redactChanges } from './redaction.js';

export interface AuditEventInput {
  readonly actorUserId?: string | null;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId?: string | undefined;
  readonly changes?: Record<string, unknown> | undefined;
  readonly meta?: { ip?: string | undefined; userAgent?: string | undefined } | undefined;
}

export interface AuditEventView {
  readonly id: string;
  readonly actorUserId: string | null;
  readonly action: string;
  readonly resourceType: string;
  readonly resourceId: string | null;
  readonly changes: Record<string, unknown> | null;
  readonly ip: string | null;
  readonly userAgent: string | null;
  readonly createdAt: Date;
}

export interface AuditListQuery {
  readonly limit: number;
  readonly offset?: number;
}

/**
 * Append-only by construction: this service exposes `record` and `list` and nothing else.
 * A caller with database rights can still UPDATE or DELETE — production deployments should
 * grant the application role INSERT and SELECT only (documented in README).
 */
@Injectable()
export class AuditLogService {
  constructor(private readonly prisma: PrismaService) {}

  async record(event: AuditEventInput): Promise<AuditEventView> {
    const row = await this.prisma.auditLog.create({
      data: {
        actorUserId: event.actorUserId ?? null,
        action: event.action,
        resourceType: event.resourceType,
        resourceId: event.resourceId ?? null,
        changes: redactChanges(event.changes) as Prisma.InputJsonValue,
        ip: event.meta?.ip ?? null,
        userAgent: event.meta?.userAgent ?? null,
      },
    });
    return toView(row);
  }

  async list(query: AuditListQuery): Promise<AuditEventView[]> {
    const rows = await this.prisma.auditLog.findMany({
      orderBy: { id: 'desc' },
      take: query.limit,
      skip: query.offset ?? 0,
    });
    return rows.map(toView);
  }
}

function toView(row: {
  id: bigint;
  actorUserId: string | null;
  action: string;
  resourceType: string;
  resourceId: string | null;
  changes: Prisma.JsonValue;
  ip: string | null;
  userAgent: string | null;
  createdAt: Date;
}): AuditEventView {
  return {
    id: row.id.toString(),
    actorUserId: row.actorUserId,
    action: row.action,
    resourceType: row.resourceType,
    resourceId: row.resourceId,
    changes:
      typeof row.changes === 'object' && row.changes !== null && !Array.isArray(row.changes)
        ? row.changes
        : null,
    ip: row.ip,
    userAgent: row.userAgent,
    createdAt: row.createdAt,
  };
}
