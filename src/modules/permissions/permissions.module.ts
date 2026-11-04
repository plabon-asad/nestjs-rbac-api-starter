import { Module } from '@nestjs/common';
import { AuditLogsModule } from '../audit-logs/audit-logs.module.js';
import { PermissionsController } from './controllers/permissions.controller.js';
import { PermissionsService } from './services/permissions.service.js';

@Module({
  imports: [AuditLogsModule],
  controllers: [PermissionsController],
  providers: [PermissionsService],
  exports: [PermissionsService],
})
export class PermissionsModule {}
