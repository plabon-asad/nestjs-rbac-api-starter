import { PasswordService } from '../../src/modules/auth/services/password.service.js';
import { prisma } from './prisma-test.js';

const passwords = new PasswordService({ memoryCost: 8_192, timeCost: 2, parallelism: 1 });

/** Minimal account fixture for auth and RBAC tests. */
export async function seedUser(
  email: string,
  password: string,
  overrides: { status?: 'ACTIVE' | 'DISABLED' | 'LOCKED' } = {},
): Promise<string> {
  const user = await prisma.user.create({
    data: {
      email: email.toLowerCase(),
      passwordHash: await passwords.hash(password),
      firstName: 'Fixture',
      lastName: 'User',
      status: overrides.status ?? 'ACTIVE',
    },
  });
  return user.id;
}
