import { SetMetadata } from '@nestjs/common';

export const AUTHENTICATED_ONLY_KEY = 'rbac:authenticated-only';

/**
 * Marks a self-service route (own profile, own sessions, own password) as needing a valid
 * access token but no particular permission. The service layer must still scope every query
 * to the caller, and the startup policy scan accepts this as an explicit declaration.
 */
export const AuthenticatedOnly = (): MethodDecorator & ClassDecorator =>
  SetMetadata(AUTHENTICATED_ONLY_KEY, true);
