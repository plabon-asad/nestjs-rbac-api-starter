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
