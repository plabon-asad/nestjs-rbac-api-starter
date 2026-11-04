import { Module } from '@nestjs/common';
import { AuditLogsModule } from '../audit-logs/audit-logs.module.js';
import { AuthzModule } from '../authz/authz.module.js';
import { PermissionOverridesController } from './controllers/permission-overrides.controller.js';
import { PermissionOverridesService } from './services/permission-overrides.service.js';

@Module({
  imports: [AuthzModule, AuditLogsModule],
  controllers: [PermissionOverridesController],
  providers: [PermissionOverridesService],
  exports: [PermissionOverridesService],
})
export class PermissionOverridesModule {}
