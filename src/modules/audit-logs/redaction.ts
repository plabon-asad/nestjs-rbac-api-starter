const SENSITIVE_KEY = /password|token|secret|hash|cookie|authorization|credential/i;
const MAX_DEPTH = 6;

/**
 * Redaction happens at write time, before anything reaches the database: a value stored in
 * clear text can be read by anyone with database access, no matter what the API promises.
 * Sensitive keys are dropped entirely; recursion stops at a bounded depth.
 */
export function redactChanges(input?: Record<string, unknown>): Record<string, unknown> {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    return {};
  }
  return redactObject(input, 0);
}

function redactObject(value: object, depth: number): Record<string, unknown> {
  if (depth >= MAX_DEPTH) {
    return {};
  }
  const out: Record<string, unknown> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (SENSITIVE_KEY.test(key)) {
      continue;
    }
    out[key] = redactValue(entry, depth + 1);
  }
  return out;
}

function redactValue(value: unknown, depth: number): unknown {
  if (depth >= MAX_DEPTH) {
    return '[truncated]';
  }
  if (Array.isArray(value)) {
    return value.map((entry) => redactValue(entry, depth + 1));
  }
  if (typeof value === 'object' && value !== null) {
    return redactObject(value, depth);
  }
  return value;
}
