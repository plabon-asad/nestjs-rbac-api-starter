import { z } from 'zod';

const email = z.email().trim().toLowerCase();
const password = z.string().min(1).max(255);
// OWASP guidance: prioritize length over composition rules.
const newPasswordPolicy = z.string().min(12, 'Password must be at least 12 characters').max(255);

export const loginSchema = z.object({ email, password });

export const refreshSchema = z.object({ refreshToken: z.string().min(1).optional() });

export const logoutSchema = z.object({ refreshToken: z.string().min(1).optional() });

export const forgotPasswordSchema = z.object({ email });

export const resetPasswordSchema = z.object({
  token: z.string().min(16).max(255),
  newPassword: newPasswordPolicy,
});

export const changePasswordSchema = z.object({
  currentPassword: password,
  newPassword: newPasswordPolicy,
});

export type LoginDto = z.infer<typeof loginSchema>;
export type RefreshDto = z.infer<typeof refreshSchema>;
export type LogoutDto = z.infer<typeof logoutSchema>;
export type ForgotPasswordDto = z.infer<typeof forgotPasswordSchema>;
export type ResetPasswordDto = z.infer<typeof resetPasswordSchema>;
export type ChangePasswordDto = z.infer<typeof changePasswordSchema>;
