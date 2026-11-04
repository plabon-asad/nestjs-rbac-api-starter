import { Module } from '@nestjs/common';
import { AuditLogsController } from './controllers/audit-logs.controller.js';
import { AuditLogService } from './audit-log.service.js';

@Module({
  controllers: [AuditLogsController],
  providers: [AuditLogService],
  exports: [AuditLogService],
})
export class AuditLogsModule {}
