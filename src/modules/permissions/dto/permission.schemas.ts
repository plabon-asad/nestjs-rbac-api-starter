import { z } from 'zod';
import { isPermissionSlug } from '../../../database/seeds/rbac-catalogue.js';

const slug = z
  .string()
  .min(1)
  .max(60)
  .refine(isPermissionSlug, 'Must be a lowercase slug: letters, digits, "-" or "_"');
const label = z.string().trim().min(1).max(120);
const prose = z.string().trim().max(500);

export const createPermissionSchema = z.object({
  resource: slug,
  action: slug,
  name: label,
  description: prose.optional(),
});

/** `resource`/`action` are deliberately absent: changing them would orphan existing grants. */
export const updatePermissionSchema = z.object({
  name: label.optional(),
  description: prose.nullable().optional(),
});

export const permissionIdSchema = z.string().min(1).max(64);

export type CreatePermissionDto = z.infer<typeof createPermissionSchema>;
export type UpdatePermissionDto = z.infer<typeof updatePermissionSchema>;
