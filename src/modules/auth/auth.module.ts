import { Module, Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_ENV } from '../../config/app.config.js';
import type { AppEnvironment } from '../../config/env.validation.js';
import { AuthController } from './controllers/auth.controller.js';
import { JwtAuthGuard } from './guards/jwt-auth.guard.js';
import { MailerPort } from './interfaces/mailer.port.js';
import { AuthService } from './services/auth.service.js';
import { ConsoleMailer } from './services/console-mailer.js';
import { PasswordService } from './services/password.service.js';
import { RefreshTokenService } from './services/refresh-token.service.js';
import { TokenService } from './services/token.service.js';

const tokenServiceProvider: Provider<TokenService> = {
  provide: TokenService,
  useFactory: (env: AppEnvironment) => new TokenService(env),
  inject: [APP_ENV],
};

const mailerProvider: Provider = {
  provide: MailerPort,
  useClass: ConsoleMailer,
};

const passwordServiceProvider: Provider<PasswordService> = {
  provide: PasswordService,
  useFactory: () => new PasswordService(),
};

@Module({
  imports: [
    ThrottlerModule.forRootAsync({
      inject: [APP_ENV],
      useFactory: (env: AppEnvironment) => ({
        throttlers: [{ ttl: env.throttle.ttlSeconds * 1000, limit: env.throttle.limit }],
      }),
    }),
  ],
  controllers: [AuthController],
  providers: [
    AuthService,
    passwordServiceProvider,
    RefreshTokenService,
    tokenServiceProvider,
    mailerProvider,
    { provide: APP_GUARD, useClass: ThrottlerGuard },
    { provide: APP_GUARD, useClass: JwtAuthGuard },
  ],
  exports: [AuthService, TokenService, RefreshTokenService, PasswordService],
})
export class AuthModule {}
