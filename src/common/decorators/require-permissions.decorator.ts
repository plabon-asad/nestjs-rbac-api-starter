import { applyDecorators, SetMetadata } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation } from '@nestjs/swagger';

export const REQUIRE_PERMISSIONS_KEY = 'rbac:required-permissions';

export type PermissionMode = 'and' | 'or';

export interface PermissionRequirement {
  readonly keys: readonly string[];
  readonly mode: PermissionMode;
}

/**
 * Declares the server-side permission keys a route needs. Defaults to AND (fail closed);
 * pass `{ mode: 'or' }` to accept any one of the keys. An empty list is rejected because
 * `[]` under AND would be vacuously true and would quietly open the route.
 *
 * The OpenAPI bearer requirement and permission description ride along with the guard
 * metadata, so documentation can never drift from enforcement: one decorator, both effects.
 */
export function RequirePermissions(
  keys: string | readonly string[],
  options?: { readonly mode?: PermissionMode },
): MethodDecorator & ClassDecorator {
  const list = typeof keys === 'string' ? [keys] : [...keys];
  if (list.length === 0) {
    throw new Error(
      '@RequirePermissions() needs at least one permission key — use @Public() or @AuthenticatedOnly()',
    );
  }
  const mode = options?.mode ?? 'and';
  const requirement = { keys: list, mode } satisfies PermissionRequirement;

  const guard = SetMetadata(REQUIRE_PERMISSIONS_KEY, requirement);
  const methodDecorators = applyDecorators(
    guard,
    ApiBearerAuth('bearerAuth'),
    ApiOperation({
      description: `Requires permission: ${list.join(mode === 'or' ? ' or ' : ' and ')}.`,
    }),
  );

  function decorate(
    target: object,
    propertyKey?: string | symbol,
    descriptor?: TypedPropertyDescriptor<unknown>,
  ): void {
    if (propertyKey !== undefined && descriptor !== undefined) {
      methodDecorators(target, propertyKey, descriptor);
      return;
    }
    // Class-level usage has no method descriptor, and the Swagger decorators would throw
    // on undefined; the guard metadata alone still composes for handlers without their own.
    if (typeof target === 'function') {
      guard(target);
    }
  }

  return decorate as MethodDecorator & ClassDecorator;
}
