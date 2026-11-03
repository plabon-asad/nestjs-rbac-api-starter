import 'dotenv/config';
import { defineConfig, env } from 'prisma/config';

const provider = process.env.DATABASE_PROVIDER ?? 'postgresql';

export default defineConfig({
  schema: `prisma/schema.${provider}.prisma`,
  migrations: {
    path: `prisma/migrations/${provider}`,
    seed: 'tsx prisma/seed.ts',
  },
  datasource: {
    url: env('DATABASE_URL'),
  },
});
