import { z } from 'zod';

const ROLE_NAME_PATTERN = /^[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*$/;
const PERMISSION_KEY_PATTERN = /^[a-z0-9]+(?:[-_][a-z0-9]+)*\.[a-z0-9]+(?:[-_][a-z0-9]+)*$/;

const roleSlug = z
  .string()
  .trim()
  .min(2)
  .max(60)
  .regex(ROLE_NAME_PATTERN, 'Must be a slug: letters, digits, "-" or "_"');
const permissionKey = z
  .string()
  .regex(PERMISSION_KEY_PATTERN, 'Must be an existing "resource.action" permission key');
const prose = z.string().trim().max(500);

export const createRoleSchema = z.object({
  name: roleSlug,
  description: prose.optional(),
  /**
   * `isSystem` is intentionally absent: system roles are a code decision, so no API call
   * can mint a role that bypasses the permission evaluation engine.
   */
  permissionKeys: z.array(permissionKey).max(500).default([]),
});

export const updateRoleSchema = z.object({
  name: roleSlug.optional(),
  description: prose.nullable().optional(),
});

export const setRolePermissionsSchema = z.object({
  permissionKeys: z.array(permissionKey).max(500),
});

export const roleIdSchema = z.string().min(1).max(64);

export type CreateRoleDto = z.input<typeof createRoleSchema>;
export type UpdateRoleDto = z.infer<typeof updateRoleSchema>;
export type SetRolePermissionsDto = z.infer<typeof setRolePermissionsSchema>;
