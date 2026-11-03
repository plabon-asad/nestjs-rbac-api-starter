import { spawnSync } from 'node:child_process';
import 'dotenv/config';

// Applies committed migrations to the isolated test database (TEST_DATABASE_URL).
const target = process.env.TEST_DATABASE_URL ?? process.env.DATABASE_URL;
if (!target) {
  console.error('Set TEST_DATABASE_URL or DATABASE_URL in .env');
  process.exit(1);
}

const result = spawnSync('prisma', ['migrate', 'deploy'], {
  stdio: 'inherit',
  env: { ...process.env, DATABASE_URL: target },
});
process.exit(result.status ?? 1);
