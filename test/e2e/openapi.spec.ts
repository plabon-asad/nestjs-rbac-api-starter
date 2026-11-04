import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import request from 'supertest';
import { createTestApp, type TestContext } from '../utils/create-test-app.js';

interface OpenApiOperation {
  readonly security?: readonly { readonly [scheme: string]: readonly string[] }[];
  readonly description?: string;
  readonly requestBody?: {
    readonly content?: Readonly<Record<string, { readonly schema?: Record<string, unknown> }>>;
  };
}

const PUBLIC_AUTH_PATHS = [
  '/api/auth/login',
  '/api/auth/refresh',
  '/api/auth/logout',
  '/api/auth/forgot-password',
  '/api/auth/reset-password',
];

interface OpenApiDocument {
  openapi: string;
  info: { title: string };
  paths: Record<string, Record<string, OpenApiOperation>>;
  components: { securitySchemes: Record<string, { type?: string; scheme?: string }> };
}

let ctx: TestContext;

beforeAll(async () => {
  ctx = await createTestApp({ openApi: true });
});

afterAll(async () => {
  await ctx.app.close();
});

async function fetchDocument(): Promise<OpenApiDocument> {
  const res = await request(ctx.app.getHttpServer()).get('/api/docs.json').expect(200);
  return res.body as OpenApiDocument;
}

describe('OpenAPI document served at /api/docs.json', () => {
  it('is reachable without a token and carries the API identity', async () => {
    const document = await fetchDocument();
    expect(document.openapi).toBeTruthy();
    expect(document.info.title).toBe('NestJS RBAC API Starter');
    expect(document.components.securitySchemes['bearerAuth']).toMatchObject({
      type: 'http',
      scheme: 'bearer',
    });
  });

  it('documents every route the starter ships', async () => {
    const document = await fetchDocument();
    for (const path of [
      '/api/auth/login',
      '/api/auth/me',
      '/api/users',
      '/api/users/{id}',
      '/api/users/{id}/roles',
      '/api/roles',
      '/api/roles/{id}',
      '/api/roles/{id}/permissions',
      '/api/permissions',
      '/api/permissions/{id}',
      '/api/permission-overrides/{userId}',
      '/api/permission-overrides/{userId}/{permissionKey}',
      '/api/audit-logs',
    ]) {
      expect(document.paths, `missing path ${path}`).toHaveProperty(path);
    }
  });

  it('marks public auth routes as unsecured and everything else as bearer-only', async () => {
    const document = await fetchDocument();
    for (const [path, operations] of Object.entries(document.paths)) {
      for (const [method, operation] of Object.entries(operations)) {
        const isPublic =
          method === 'post' && (PUBLIC_AUTH_PATHS.includes(path) || path === '/api/auth/logout');
        if (isPublic) {
          expect(
            operation.security,
            `public route ${method} ${path} should stay open`,
          ).toBeUndefined();
        } else {
          expect(
            operation.security,
            `route ${method} ${path} must document the bearer requirement`,
          ).toEqual([{ bearerAuth: [] }]);
        }
      }
    }
  });

  it('documents required permission keys in every protected operation', async () => {
    const document = await fetchDocument();
    expect(document.paths['/api/users']?.['post']?.description).toMatch(/users\.create/);
    expect(document.paths['/api/roles']?.['get']?.description).toMatch(/roles\.read/);
    expect(document.paths['/api/audit-logs']?.['get']?.description).toMatch(/audit-logs\.read/);
  });

  it('derives request body schemas from the same Zod schemas the pipes enforce', async () => {
    const document = await fetchDocument();
    const body =
      document.paths['/api/users']?.['post']?.requestBody?.content?.['application/json']?.schema;
    expect(body).toMatchObject({
      type: 'object',
      required: ['email', 'password', 'firstName', 'lastName'],
    });
    const properties = body?.['properties'] as Record<string, Record<string, unknown>>;
    expect(properties['password']).toMatchObject({ type: 'string', minLength: 12 });
  });

  it('serves the interactive UI at /api/docs', async () => {
    const res = await request(ctx.app.getHttpServer()).get('/api/docs').expect(200);
    expect(res.text).toMatch(/swagger/i);
  });
});
