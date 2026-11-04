import type { INestApplication } from '@nestjs/common';
import {
  DocumentBuilder,
  SwaggerModule,
  type OpenAPIObject,
  type SchemaObject,
} from '@nestjs/swagger';
import { z, type ZodType } from 'zod';

/**
 * Request bodies are documented from the very Zod schemas the validation pipes enforce,
 * so the OpenAPI spec can never drift away from what the API actually accepts.
 */
export function zodBody(schema: ZodType): { schema: SchemaObject } {
  const jsonSchema = z.toJSONSchema(schema, { io: 'input' }) as Record<string, unknown>;
  delete jsonSchema['$schema'];
  return { schema: jsonSchema };
}

export function createOpenApiDocument(app: INestApplication): OpenAPIObject {
  const config = new DocumentBuilder()
    .setTitle('NestJS RBAC API Starter')
    .setDescription(
      'Role-based access control API. Access tokens carry identity only — permissions are ' +
        'evaluated server-side on every request, so revocations take effect immediately. ' +
        'Unmarked endpoints require no permission; otherwise the required permission key is ' +
        'named in each operation description.',
    )
    .setVersion('0.1.0')
    .addBearerAuth(
      {
        type: 'http',
        scheme: 'bearer',
        description: 'JWT access token from POST /api/auth/login',
      },
      'bearerAuth',
    )
    .build();
  return SwaggerModule.createDocument(app, config);
}

export function setupOpenApi(app: INestApplication): void {
  SwaggerModule.setup('api/docs', app, () => createOpenApiDocument(app), {
    jsonDocumentUrl: 'api/docs.json',
    swaggerOptions: { persistAuthorization: true },
  });
}
