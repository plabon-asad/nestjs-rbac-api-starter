import { z } from 'zod';

const PERMISSION_KEY_PATTERN = /^[a-z0-9]+(?:[-_][a-z0-9]+)*\.[a-z0-9]+(?:[-_][a-z0-9]+)*$/;

export const permissionKeySchema = z
  .string()
  .regex(PERMISSION_KEY_PATTERN, 'Must be a "resource.action" permission key');

export const userIdSchema = z.string().min(1).max(64);

/** `INHERIT` is a command, not a stored state: it deletes the row so the role grants decide. */
export const setOverrideSchema = z.object({
  effect: z.enum(['ALLOW', 'DENY', 'INHERIT']),
});

export type SetOverrideDto = z.infer<typeof setOverrideSchema>;
export type OverrideEffectInput = SetOverrideDto['effect'];
