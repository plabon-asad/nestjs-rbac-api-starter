import { SetMetadata } from '@nestjs/common';

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

  return SetMetadata(REQUIRE_PERMISSIONS_KEY, {
    keys: list,
    mode: options?.mode ?? 'and',
  } satisfies PermissionRequirement);
}
