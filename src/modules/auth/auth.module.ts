import { Module, Provider } from '@nestjs/common';
import { APP_ENV } from '../../config/app.config.js';
import type { AppEnvironment } from '../../config/env.validation.js';
import { AuditLogsModule } from '../audit-logs/audit-logs.module.js';
import { AuthzModule } from '../authz/authz.module.js';
import { AuthController } from './controllers/auth.controller.js';
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
  imports: [AuditLogsModule, AuthzModule],
  controllers: [AuthController],
  providers: [
    AuthService,
    passwordServiceProvider,
    RefreshTokenService,
    tokenServiceProvider,
    mailerProvider,
  ],
  exports: [AuthService, TokenService, RefreshTokenService, PasswordService],
})
export class AuthModule {}
