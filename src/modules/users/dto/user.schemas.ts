import { z } from 'zod';

const ROLE_NAME_PATTERN = /^[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)*$/;

const email = z.email().trim().toLowerCase();
// OWASP guidance: prioritize length over composition rules.
const initialPassword = z.string().min(12, 'Password must be at least 12 characters').max(255);
const personName = z.string().trim().min(1).max(120);
const roleSlug = z
  .string()
  .trim()
  .min(2)
  .max(60)
  .regex(ROLE_NAME_PATTERN, 'Must be a slug: letters, digits, "-" or "_"');

export const createUserSchema = z.object({
  email,
  password: initialPassword,
  firstName: personName,
  lastName: personName,
  roleNames: z.array(roleSlug).max(50).default([]),
});

export const updateUserSchema = z
  .object({
    firstName: personName.optional(),
    lastName: personName.optional(),
    /**
     * LOCKED is intentionally absent: lockouts are owned by the auth mechanism, and an admin
     * force-lock is exactly what DISABLED already expresses.
     */
    status: z.enum(['ACTIVE', 'DISABLED']).optional(),
  })
  .refine((value) => Object.values(value).some((entry) => entry !== undefined), {
    message: 'Provide at least one field to update',
  });

export const assignRolesSchema = z.object({
  roleNames: z.array(roleSlug).max(50),
});

export const userIdSchema = z.string().min(1).max(64);

export type CreateUserDto = z.input<typeof createUserSchema>;
export type UpdateUserDto = z.infer<typeof updateUserSchema>;
export type AssignRolesDto = z.infer<typeof assignRolesSchema>;
