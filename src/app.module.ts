import { Module } from '@nestjs/common';
import { CoreModule } from './config/core.module.js';
import { AuthModule } from './modules/auth/auth.module.js';
import { PermissionsModule } from './modules/permissions/permissions.module.js';
import { RolesModule } from './modules/roles/roles.module.js';

@Module({
  imports: [CoreModule, AuthModule, RolesModule, PermissionsModule],
})
export class AppModule {}
