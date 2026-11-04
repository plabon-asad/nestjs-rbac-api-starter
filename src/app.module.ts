import { Module, type Provider } from '@nestjs/common';
import { APP_GUARD } from '@nestjs/core';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_ENV } from './config/app.config.js';
import type { AppEnvironment } from './config/env.validation.js';
import { CoreModule } from './config/core.module.js';
import { AuditLogsModule } from './modules/audit-logs/audit-logs.module.js';
import { AuthModule } from './modules/auth/auth.module.js';
import { JwtAuthGuard } from './modules/auth/guards/jwt-auth.guard.js';
import { AuthzModule } from './modules/authz/authz.module.js';
import { PermissionsGuard } from './modules/authz/guards/permissions.guard.js';
import { PermissionsModule } from './modules/permissions/permissions.module.js';
import { PermissionOverridesModule } from './modules/permission-overrides/permission-overrides.module.js';
import { RolesModule } from './modules/roles/roles.module.js';
import { UsersModule } from './modules/users/users.module.js';

/**
 * The global guard chain, in execution order: ThrottlerGuard -> JwtAuthGuard -> PermissionsGuard.
 * Guards from the root module run before those of imported modules, so the whole chain is one
 * ordered list in the composition root (exported so test apps register the identical chain).
 */
export const globalGuardProviders: readonly Provider[] = [
  { provide: APP_GUARD, useClass: ThrottlerGuard },
  { provide: APP_GUARD, useClass: JwtAuthGuard },
  { provide: APP_GUARD, useClass: PermissionsGuard },
] as const;

export const throttlerModule = ThrottlerModule.forRootAsync({
  inject: [APP_ENV],
  useFactory: (env: AppEnvironment) => ({
    throttlers: [{ ttl: env.throttle.ttlSeconds * 1000, limit: env.throttle.limit }],
  }),
});

@Module({
  imports: [
    CoreModule,
    throttlerModule,
    AuthModule,
    UsersModule,
    RolesModule,
    PermissionsModule,
    PermissionOverridesModule,
    AuditLogsModule,
    AuthzModule,
  ],
  providers: [...globalGuardProviders],
})
export class AppModule {}
