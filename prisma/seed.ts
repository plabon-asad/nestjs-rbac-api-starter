import 'dotenv/config';
import { loadAppEnv } from '../src/config/app.config.js';
import { PrismaService } from '../src/database/prisma/prisma.service.js';
import { seedRbac } from '../src/database/seeds/seed-rbac.js';
import { PasswordService } from '../src/modules/auth/services/password.service.js';

async function main(): Promise<void> {
  const env = loadAppEnv();
  const prisma = new PrismaService(env);

  try {
    const result = await seedRbac(prisma, {
      superAdmin: env.superAdmin,
      // Production argon2 parameters: a seeded hash must be as strong as any other.
      passwords: new PasswordService(),
    });

    console.log(
      `RBAC seed: ${result.permissionCount} permissions, ${result.roleCount} roles, ` +
        (result.superAdminCreated
          ? `super admin ${env.superAdmin.email} created`
          : `super admin ${env.superAdmin.email} already existed (password preserved)`),
    );
  } finally {
    await prisma.$disconnect();
  }
}

await main();
