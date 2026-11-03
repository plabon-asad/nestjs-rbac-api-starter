import { Prisma } from '../../generated/prisma/client.js';

const UNIQUE_CONSTRAINT_VIOLATION = 'P2002';

/**
 * Both adapters surface a unique-index violation as P2002, so callers can map it to
 * 409 without knowing which database is configured. `meta.target` carries the index name
 * when the driver reports it, which is enough to tell two constraints apart.
 */
export function isUniqueViolation(
  error: unknown,
): error is Prisma.PrismaClientKnownRequestError & { code: typeof UNIQUE_CONSTRAINT_VIOLATION } {
  return (
    error instanceof Prisma.PrismaClientKnownRequestError &&
    error.code === UNIQUE_CONSTRAINT_VIOLATION
  );
}
