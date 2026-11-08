import type { User } from '../../../generated/prisma/client.js';

/** Whitelisted projection — never expose raw Prisma rows to HTTP clients. */
export interface UserView {
  readonly id: string;
  readonly email: string;
  readonly firstName: string;
  readonly lastName: string;
  readonly status: User['status'];
  readonly createdAt: Date;
  readonly updatedAt: Date;
}

export interface AuthTokensView {
  readonly accessToken: string;
  readonly refreshToken: string;
}

export interface LoginResultView extends AuthTokensView {
  readonly user: UserView;
}

/**
 * The current session's identity plus the authorization facts a client needs to
 * gate navigation and actions. `permissions` is the authoritative effective set
 * recomputed server-side; a system-role holder receives the whole catalogue.
 */
export interface SessionAccessView {
  readonly user: UserView;
  readonly roles: readonly string[];
  readonly permissions: readonly string[];
}

export function toUserView(user: User): UserView {
  return {
    id: user.id,
    email: user.email,
    firstName: user.firstName,
    lastName: user.lastName,
    status: user.status,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
  };
}
