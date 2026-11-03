import { parseEnv, type AppEnvironment } from './env.validation.js';

export const APP_ENV = Symbol('APP_ENV');

export function loadAppEnv(source: NodeJS.ProcessEnv = process.env): AppEnvironment {
  return parseEnv(source);
}

export type { AppEnvironment };
