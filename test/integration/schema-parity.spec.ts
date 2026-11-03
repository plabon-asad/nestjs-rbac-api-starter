import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';
import { checkSchemaParity } from '../../scripts/prisma-database.js';

const postgresPath = fileURLToPath(
  new URL('../../prisma/schema.postgresql.prisma', import.meta.url),
);
const mysqlPath = fileURLToPath(new URL('../../prisma/schema.mysql.prisma', import.meta.url));

const PG_HEADER = `datasource db {\n  provider = "postgresql"\n}\n`;
const MY_HEADER = `datasource db {\n  provider = "mysql"\n}\n`;

describe('checkSchemaParity', () => {
  it('accepts schemas that differ only in provider and @db type mappings', () => {
    const issues = checkSchemaParity(
      `${PG_HEADER}\nmodel Widget {\n  id String @id\n  bio  String @db.Text\n}\n`,
      `${MY_HEADER}\nmodel Widget {\n  id String @id\n  bio  String @db.LongText\n}\n`,
    );
    expect(issues).toEqual([]);
  });

  it('reports a field present in only one schema', () => {
    const issues = checkSchemaParity(
      `${PG_HEADER}\nmodel Widget {\n  id String @id\n  extra String\n}\n`,
      `${MY_HEADER}\nmodel Widget {\n  id String @id\n}\n`,
    );
    expect(issues.length).toBeGreaterThan(0);
    expect(issues.join('\n')).toMatch(/extra/);
  });

  it('reports a missing model', () => {
    const issues = checkSchemaParity(
      `${PG_HEADER}\nmodel A {\n  id String @id\n}\nmodel B {\n  id String @id\n}\n`,
      `${MY_HEADER}\nmodel A {\n  id String @id\n}\n`,
    );
    expect(issues.join('\n')).toMatch(/model B/i);
  });

  it('ignores enum declarations in parity comparison', () => {
    const issues = checkSchemaParity(
      `${PG_HEADER}\nenum Status {\n  ACTIVE\n}\nmodel Widget {\n  id String @id\n}\n`,
      `${MY_HEADER}\nenum Status {\n  ACTIVE\n}\nmodel Widget {\n  id String @id\n}\n`,
    );
    expect(issues).toEqual([]);
  });

  it('the shipped postgresql and mysql schemas are in parity', async () => {
    const [pg, my] = await Promise.all([
      readFile(postgresPath, 'utf8'),
      readFile(mysqlPath, 'utf8'),
    ]);
    expect(checkSchemaParity(pg, my)).toEqual([]);
  });
});
