import {
  Body,
  Controller,
  Get,
  HttpCode,
  Post,
  Req,
  Res,
  UnauthorizedException,
} from '@nestjs/common';
import type { CookieOptions, Request, Response } from 'express';
import { Public } from '../../../common/decorators/public.decorator.js';
import { CurrentUser } from '../../../common/decorators/current-user.decorator.js';
import { ZodValidationPipe } from '../../../common/pipes/zod-validation.pipe.js';
import { AuthService } from '../services/auth.service.js';
import type { RequestMeta } from '../services/refresh-token.service.js';
import {
  changePasswordSchema,
  forgotPasswordSchema,
  loginSchema,
  logoutSchema,
  refreshSchema,
  resetPasswordSchema,
  type ChangePasswordDto,
  type ForgotPasswordDto,
  type LoginDto,
  type LogoutDto,
  type RefreshDto,
  type ResetPasswordDto,
} from '../dto/auth.schemas.js';
import type { AuthTokensView, LoginResultView, UserView } from '../models/auth-views.js';
import type { AuthenticatedUser } from '../../../common/interfaces/authenticated-user.interface.js';

const SESSION_COOKIE = 'refresh_token';

@Controller('auth')
export class AuthController {
  constructor(private readonly auth: AuthService) {}

  @Public()
  @Post('login')
  @HttpCode(200)
  async login(
    @Body(new ZodValidationPipe(loginSchema)) dto: LoginDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<LoginResultView> {
    const result = await this.auth.login(dto.email, dto.password, this.meta(req));
    this.setSessionCookie(res, result.refreshToken);
    return result;
  }

  @Public()
  @Post('refresh')
  @HttpCode(200)
  async refresh(
    @Body(new ZodValidationPipe(refreshSchema)) dto: RefreshDto,
    @Req() req: Request,
    @Res({ passthrough: true }) res: Response,
  ): Promise<AuthTokensView> {
    const cookies = req.cookies as Record<string, string> | undefined;
    const token = dto.refreshToken ?? cookies?.[SESSION_COOKIE];
    if (typeof token !== 'string' || token.length === 0) {
      throw new UnauthorizedException('Refresh token is invalid or expired');
    }
    const result = await this.auth.refresh(token, this.meta(req));
    this.setSessionCookie(res, result.refreshToken);
    return result;
  }

  @Public()
  @Post('logout')
  @HttpCode(204)
  async logout(
    @Body(new ZodValidationPipe(logoutSchema)) dto: LogoutDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<void> {
    await this.auth.logout(dto.refreshToken ?? undefined);
    res.clearCookie(SESSION_COOKIE, this.cookieOptions());
  }

  @Post('logout-all')
  @HttpCode(204)
  async logoutAll(@CurrentUser() user: AuthenticatedUser): Promise<void> {
    await this.auth.logoutAll(user.id);
  }

  @Public()
  @Post('forgot-password')
  @HttpCode(202)
  async forgotPassword(
    @Body(new ZodValidationPipe(forgotPasswordSchema)) dto: ForgotPasswordDto,
  ): Promise<void> {
    await this.auth.forgotPassword(dto.email);
  }

  @Public()
  @Post('reset-password')
  @HttpCode(204)
  async resetPassword(
    @Body(new ZodValidationPipe(resetPasswordSchema)) dto: ResetPasswordDto,
  ): Promise<void> {
    await this.auth.resetPassword(dto.token, dto.newPassword);
  }

  @Post('change-password')
  @HttpCode(204)
  async changePassword(
    @CurrentUser() user: AuthenticatedUser,
    @Body(new ZodValidationPipe(changePasswordSchema)) dto: ChangePasswordDto,
  ): Promise<void> {
    await this.auth.changePassword(user.id, dto.currentPassword, dto.newPassword);
  }

  @Get('me')
  async me(@CurrentUser() user: AuthenticatedUser): Promise<UserView> {
    return this.auth.me(user.id);
  }

  private meta(req: Request): RequestMeta {
    return { ip: req.ip, userAgent: req.headers['user-agent'] };
  }

  private cookieOptions(): CookieOptions {
    return {
      httpOnly: true,
      secure: this.auth.cookieSecure,
      sameSite: 'lax',
      path: '/api/auth',
      maxAge: this.auth.cookieMaxAgeMs,
    };
  }

  private setSessionCookie(res: Response, refreshToken: string): void {
    res.cookie(SESSION_COOKIE, refreshToken, this.cookieOptions());
  }
}
