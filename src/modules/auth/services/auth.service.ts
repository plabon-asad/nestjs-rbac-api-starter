import { BadRequestException, Inject, Injectable, UnauthorizedException } from '@nestjs/common';
import { APP_ENV } from '../../../config/app.config.js';
import { createHash, randomBytes } from 'node:crypto';
import { PrismaService } from '../../../database/prisma/prisma.service.js';
import type { AppEnvironment } from '../../../config/env.validation.js';
import { PasswordService } from './password.service.js';
import { TokenService } from './token.service.js';
import { RefreshTokenService, type RequestMeta } from './refresh-token.service.js';
import { MailerPort } from '../interfaces/mailer.port.js';
import {
  toUserView,
  type AuthTokensView,
  type LoginResultView,
  type UserView,
} from '../models/auth-views.js';

const INVALID_CREDENTIALS = 'Invalid email or password.';
const MAX_FAILED_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MS = 15 * 60_000;
const PASSWORD_RESET_TTL_MS = 30 * 60_000;

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    @Inject(APP_ENV) private readonly env: AppEnvironment,
    private readonly passwords: PasswordService,
    private readonly tokens: TokenService,
    private readonly refreshTokens: RefreshTokenService,
    @Inject(MailerPort) private readonly mailer: MailerPort,
  ) {}

  async login(email: string, plaintext: string, meta: RequestMeta): Promise<LoginResultView> {
    const user = await this.prisma.user.findUnique({ where: { email } });

    if (user === null) {
      throw new UnauthorizedException(INVALID_CREDENTIALS);
    }

    if (user.lockedUntil !== null && user.lockedUntil.getTime() > Date.now()) {
      throw new UnauthorizedException(INVALID_CREDENTIALS);
    }

    if (user.status !== 'ACTIVE') {
      throw new UnauthorizedException(INVALID_CREDENTIALS);
    }

    const valid = await this.passwords.verify(user.passwordHash, plaintext);
    if (!valid) {
      await this.recordFailedLogin(user.id, user.failedLoginCount);
      throw new UnauthorizedException(INVALID_CREDENTIALS);
    }

    await this.prisma.user.update({
      where: { id: user.id },
      data: { failedLoginCount: 0, lockedUntil: null },
    });

    const session = await this.refreshTokens.issue(user.id, meta);
    const accessToken = await this.tokens.signAccessToken(user.id, session.familyId);

    return {
      accessToken,
      refreshToken: session.token,
      user: toUserView(user),
    };
  }

  async refresh(presentedRefreshToken: string, meta: RequestMeta): Promise<AuthTokensView> {
    let session;
    try {
      session = await this.refreshTokens.rotate(presentedRefreshToken, meta);
    } catch {
      throw new UnauthorizedException('Refresh token is invalid or expired');
    }

    const user = await this.prisma.user.findUnique({ where: { id: session.userId } });
    if (user === null || user.status !== 'ACTIVE') {
      await this.refreshTokens.revokeAllForUser(session.userId);
      throw new UnauthorizedException('Refresh token is invalid or expired');
    }

    const accessToken = await this.tokens.signAccessToken(user.id, session.familyId);
    return { accessToken, refreshToken: session.token };
  }

  async logout(presentedRefreshToken: string | undefined): Promise<void> {
    if (presentedRefreshToken !== undefined && presentedRefreshToken.length > 0) {
      await this.refreshTokens.revoke(presentedRefreshToken);
    }
  }

  async logoutAll(userId: string): Promise<void> {
    await this.refreshTokens.revokeAllForUser(userId);
  }

  async me(userId: string): Promise<UserView> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (user === null) {
      throw new UnauthorizedException('Session user no longer exists');
    }
    return toUserView(user);
  }

  async forgotPassword(email: string): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { email } });
    if (user === null || user.status !== 'ACTIVE') {
      return; // Always report success to the caller; never reveal existence.
    }

    const token = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Date.now() + PASSWORD_RESET_TTL_MS);

    await this.prisma.passwordResetToken.deleteMany({ where: { userId: user.id } });
    await this.prisma.passwordResetToken.create({
      data: {
        tokenHash: this.hashToken(token),
        userId: user.id,
        expiresAt,
      },
    });

    await this.mailer.sendPasswordReset(user.email, token, expiresAt);
  }

  async resetPassword(token: string, newPassword: string): Promise<void> {
    const record = await this.prisma.passwordResetToken.findUnique({
      where: { tokenHash: this.hashToken(token) },
    });

    const invalid =
      record === null || record.usedAt !== null || record.expiresAt.getTime() <= Date.now();
    if (invalid || record === null) {
      throw new BadRequestException('Reset token is invalid, expired, or already used');
    }

    await this.applyNewPassword(record.userId, newPassword);
    await this.prisma.passwordResetToken.update({
      where: { id: record.id },
      data: { usedAt: new Date() },
    });
  }

  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    const user = await this.prisma.user.findUnique({ where: { id: userId } });
    if (user === null) {
      throw new UnauthorizedException('Session user no longer exists');
    }

    const valid = await this.passwords.verify(user.passwordHash, currentPassword);
    if (!valid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    await this.applyNewPassword(userId, newPassword);
  }

  private async applyNewPassword(userId: string, newPassword: string): Promise<void> {
    const passwordHash = await this.passwords.hash(newPassword);
    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash, passwordChangedAt: new Date() },
    });
    await this.refreshTokens.revokeAllForUser(userId);
  }

  private async recordFailedLogin(userId: string, currentCount: number): Promise<void> {
    const nextCount = currentCount + 1;
    const shouldLock = nextCount >= MAX_FAILED_LOGIN_ATTEMPTS;
    await this.prisma.user.update({
      where: { id: userId },
      data: {
        failedLoginCount: nextCount,
        ...(shouldLock ? { lockedUntil: new Date(Date.now() + LOCKOUT_DURATION_MS) } : {}),
      },
    });
  }

  private hashToken(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  get sessionCookieName(): string {
    return 'refresh_token';
  }

  get cookieSecure(): boolean {
    return this.env.cookieSecure;
  }

  get cookieMaxAgeMs(): number {
    return this.env.refreshToken.ttlDays * 86_400_000;
  }
}
