import { Controller, Get, Query } from '@nestjs/common';
import { RequirePermissions } from '../../../common/decorators/require-permissions.decorator.js';
import { ZodValidationPipe } from '../../../common/pipes/zod-validation.pipe.js';
import { AuditLogService, type AuditEventView } from '../audit-log.service.js';
import { listAuditLogsSchema, type ListAuditLogsDto } from '../dto/audit-query.schemas.js';

@Controller('audit-logs')
export class AuditLogsController {
  constructor(private readonly audit: AuditLogService) {}

  @RequirePermissions('audit-logs.read')
  @Get()
  list(
    @Query(new ZodValidationPipe(listAuditLogsSchema)) query: ListAuditLogsDto,
  ): Promise<AuditEventView[]> {
    return this.audit.list(query);
  }
}
