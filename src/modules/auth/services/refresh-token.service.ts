import { Inject, Injectable } from '@nestjs/common';
import { APP_ENV } from '../../../config/app.config.js';
import { createHash, randomBytes, randomUUID } from 'node:crypto';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import type { AppEnvironment } from '../../../config/env.validation.js';
import type { RequestMeta } from '../../../common/interfaces/request-meta.interface.js';

export type { RequestMeta };

export interface IssuedRefreshToken {
  readonly token: string;
  readonly tokenHash: string;
  readonly familyId: string;
  readonly userId: string;
  readonly expiresAt: Date;
}

export class RefreshTokenInvalidError extends Error {
  constructor() {
    super('Refresh token is invalid');
    this.name = 'RefreshTokenInvalidError';
  }
}

export class RefreshTokenReuseError extends Error {
  constructor(
    readonly userId: string,
    readonly familyId: string,
  ) {
    super('Refresh token reuse detected; the entire token family has been revoked');
    this.name = 'RefreshTokenReuseError';
  }
}

@Injectable()
export class RefreshTokenService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_ENV) private readonly env: AppEnvironment,
  ) {}

  async issue(userId: string, meta: RequestMeta, familyId?: string): Promise<IssuedRefreshToken> {
    const token = randomBytes(48).toString('base64url');
    const tokenHash = this.hash(token);
    const family = familyId ?? randomUUID();
    const expiresAt = new Date(Date.now() + this.env.refreshToken.ttlDays * 86_400_000);

    await this.prisma.refreshToken.create({
      data: {
        tokenHash,
        familyId: family,
        userId,
        expiresAt,
        createdIp: meta.ip ?? null,
        createdByUserAgent: meta.userAgent ?? null,
      },
    });

    return { token, tokenHash, familyId: family, userId, expiresAt };
  }

  async rotate(presented: string, meta: RequestMeta): Promise<IssuedRefreshToken> {
    const tokenHash = this.hash(presented);

    // Errors are thrown after the transaction commits so that family
    // revocation from a reuse attempt is never rolled back.
    const outcome = await this.prisma.$transaction(async (tx) => {
      const existing = await tx.refreshToken.findUnique({ where: { tokenHash } });

      if (existing === null) {
        return { kind: 'invalid' } as const;
      }

      if (existing.revokedAt !== null) {
        // Reuse of a rotated/revoked token: assume theft, burn the whole family.
        await tx.refreshToken.updateMany({
          where: { familyId: existing.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        return { kind: 'reuse', userId: existing.userId, familyId: existing.familyId } as const;
      }

      if (existing.expiresAt.getTime() <= Date.now()) {
        return { kind: 'invalid' } as const;
      }

      // Atomic claim: if a concurrent request already rotated it, count is 0.
      const claimed = await tx.refreshToken.updateMany({
        where: { tokenHash, revokedAt: null },
        data: { revokedAt: new Date() },
      });
      if (claimed.count === 0) {
        await tx.refreshToken.updateMany({
          where: { familyId: existing.familyId, revokedAt: null },
          data: { revokedAt: new Date() },
        });
        return { kind: 'reuse', userId: existing.userId, familyId: existing.familyId } as const;
      }

      const fresh = await this.issueTo(tx, existing.userId, meta, existing.familyId);
      return { kind: 'issued', fresh } as const;
    });

    switch (outcome.kind) {
      case 'invalid':
        throw new RefreshTokenInvalidError();
      case 'reuse':
        throw new RefreshTokenReuseError(outcome.userId, outcome.familyId);
      default:
        return outcome.fresh;
    }
  }

  /** Returns the owning user id when a live token was revoked, else null. */
  async revoke(presented: string): Promise<string | null> {
    const tokenHash = this.hash(presented);
    const existing = await this.prisma.refreshToken.findUnique({
      where: { tokenHash },
      select: { userId: true, revokedAt: true },
    });
    if (existing === null || existing.revokedAt !== null) {
      return null;
    }
    await this.prisma.refreshToken.updateMany({
      where: { tokenHash, revokedAt: null },
      data: { revokedAt: new Date() },
    });
    return existing.userId;
  }

  async revokeAllForUser(userId: string): Promise<void> {
    await this.prisma.refreshToken.updateMany({
      where: { userId, revokedAt: null },
      data: { revokedAt: new Date() },
    });
  }

  private async issueTo(
    tx: Pick<PrismaService, 'refreshToken'>,
    userId: string,
    meta: RequestMeta,
    familyId: string,
  ): Promise<IssuedRefreshToken> {
    const token = randomBytes(48).toString('base64url');
    const tokenHash = this.hash(token);
    const expiresAt = new Date(Date.now() + this.env.refreshToken.ttlDays * 86_400_000);

    await tx.refreshToken.create({
      data: {
        tokenHash,
        familyId,
        userId,
        expiresAt,
        createdIp: meta.ip ?? null,
        createdByUserAgent: meta.userAgent ?? null,
      },
    });

    return { token, tokenHash, familyId, userId, expiresAt };
  }

  private hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }
}
