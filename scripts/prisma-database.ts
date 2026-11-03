import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import process from 'node:process';

const DB_TYPE_ATTRIBUTE = /@db\.[A-Za-z0-9_]+(\(\d+\))?/g;

interface SchemaBlock {
  readonly name: string;
  readonly lines: readonly string[];
}

function extractBlocks(source: string, keyword: string): SchemaBlock[] {
  const blocks: SchemaBlock[] = [];
  const pattern = new RegExp(`^\\s*${keyword}\\s+(\\w+)\\s*\\{`, 'm');
  const lines = source.split('\n');
  let current: { name: string; body: string[] } | null = null;

  for (const line of lines) {
    if (current === null) {
      const match = pattern.exec(line);
      const open = match?.[1];
      if (open !== undefined) {
        current = { name: open, body: [] };
      }
      continue;
    }
    if (/^\s*\}/.test(line)) {
      blocks.push({ name: current.name, lines: current.body });
      current = null;
      continue;
    }
    current.body.push(line);
  }
  return blocks;
}

function normalizeBlockLines(lines: readonly string[]): string[] {
  return lines
    .map((line) => line.replace(DB_TYPE_ATTRIBUTE, '').split('//')[0]!.replace(/\s+/g, ' ').trim())
    .filter((line) => line.length > 0)
    .sort();
}

function compareBlockSets(
  kind: string,
  postgres: SchemaBlock[],
  mysql: SchemaBlock[],
  issues: string[],
): void {
  const names = new Set([...postgres.map((b) => b.name), ...mysql.map((b) => b.name)]);
  for (const name of names) {
    const pgBlock = postgres.find((b) => b.name === name);
    const myBlock = mysql.find((b) => b.name === name);
    if (!pgBlock || !myBlock) {
      issues.push(`${kind} ${name}: present in only ${pgBlock ? 'postgresql' : 'mysql'} schema`);
      continue;
    }
    const pgLines = normalizeBlockLines(pgBlock.lines);
    const myLines = normalizeBlockLines(myBlock.lines);
    if (pgLines.length !== myLines.length || pgLines.some((line, i) => line !== myLines[i])) {
      for (const line of myLines) {
        if (!pgLines.includes(line)) issues.push(`${kind} ${name}: mysql-only line "${line}"`);
      }
      for (const line of pgLines) {
        if (!myLines.includes(line)) issues.push(`${kind} ${name}: postgresql-only line "${line}"`);
      }
    }
  }
}

/**
 * Returns a list of human-readable parity problems (empty array = in sync).
 * The two schemas may differ only in the datasource `provider` line and
 * `@db.*` type-mapping attributes; everything else must match line-for-line.
 */
export function checkSchemaParity(postgresSource: string, mysqlSource: string): string[] {
  const issues: string[] = [];

  const datasourceProvider = (source: string): string | undefined =>
    /datasource\s+\w+\s*\{[^}]*?provider\s*=\s*"(\w+)"/s.exec(source)?.[1];
  const pgProvider = datasourceProvider(postgresSource);
  const myProvider = datasourceProvider(mysqlSource);
  if (pgProvider !== 'postgresql')
    issues.push(`postgresql schema datasource provider is "${pgProvider}"`);
  if (myProvider !== 'mysql') issues.push(`mysql schema datasource provider is "${myProvider}"`);

  compareBlockSets(
    'model',
    extractBlocks(postgresSource, 'model'),
    extractBlocks(mysqlSource, 'model'),
    issues,
  );
  compareBlockSets(
    'enum',
    extractBlocks(postgresSource, 'enum'),
    extractBlocks(mysqlSource, 'enum'),
    issues,
  );

  return issues;
}

async function runCli(): Promise<void> {
  const [command, argument] = process.argv.slice(2);
  const load = async (path: string) => readFile(new URL(path, import.meta.url), 'utf8');

  switch (command) {
    case 'parity': {
      const issues = checkSchemaParity(
        await load('../prisma/schema.postgresql.prisma'),
        await load('../prisma/schema.mysql.prisma'),
      );
      if (issues.length > 0) {
        console.error('Prisma schema parity problems:');
        for (const issue of issues) console.error(`  - ${issue}`);
        process.exitCode = 1;
        return;
      }
      console.log('Prisma schemas are in parity.');
      return;
    }
    case 'use': {
      if (argument !== 'postgresql' && argument !== 'mysql') {
        console.error('Usage: db:use:postgres | db:use:mysql');
        process.exitCode = 1;
        return;
      }
      const issues = checkSchemaParity(
        await load('../prisma/schema.postgresql.prisma'),
        await load('../prisma/schema.mysql.prisma'),
      );
      if (issues.length > 0) {
        console.error('Refusing to switch: schema parity check failed.');
        for (const issue of issues) console.error(`  - ${issue}`);
        process.exitCode = 1;
        return;
      }
      console.log(
        `Provider selected at runtime via DATABASE_PROVIDER=${argument}; ` +
          'ensure DATABASE_URL matches, then run: pnpm prisma:generate',
      );
      return;
    }
    case 'generate': {
      const provider = process.env.DATABASE_PROVIDER ?? 'postgresql';
      if (provider !== 'postgresql' && provider !== 'mysql') {
        console.error(`Unknown DATABASE_PROVIDER "${provider}"`);
        process.exitCode = 1;
        return;
      }
      const { spawnSync } = await import('node:child_process');
      const result = spawnSync(
        'prisma',
        ['generate', '--schema', `prisma/schema.${provider}.prisma`],
        {
          stdio: 'inherit',
          shell: false,
        },
      );
      process.exitCode = result.status ?? 1;
      return;
    }
    default:
      console.error(`Unknown command "${command ?? ''}". Expected parity | use | generate.`);
      process.exitCode = 1;
  }
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  await runCli();
}
