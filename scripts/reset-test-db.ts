import { spawnSync } from 'node:child_process';
import 'dotenv/config';

// Drops and re-applies every committed migration on the isolated test database.
// No seed runs (Prisma 7's `migrate reset` does not seed, and the DB-backed suites
// truncate the tables and insert their own fixtures). Destructive and test-only:
// identifies the target solely from TEST_DATABASE_URL and never falls back to
// DATABASE_URL, so a missing variable can never wipe the development database.
const target = process.env.TEST_DATABASE_URL;
if (!target) {
  console.error(
    'Set TEST_DATABASE_URL in .env. Refusing to fall back to DATABASE_URL: reset drops all data.',
  );
  process.exit(1);
}

const result = spawnSync('prisma', ['migrate', 'reset', '--force'], {
  stdio: 'inherit',
  env: { ...process.env, DATABASE_URL: target },
});
process.exit(result.status ?? 1);
