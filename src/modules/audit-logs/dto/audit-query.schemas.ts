import { z } from 'zod';

export const listAuditLogsSchema = z.object({
  limit: z.coerce.number().int().min(1).max(200).default(50),
  offset: z.coerce.number().int().min(0).default(0),
});

/** Post-pipe shape: defaults are applied, so both fields are concrete numbers. */
export type ListAuditLogsDto = z.infer<typeof listAuditLogsSchema>;
