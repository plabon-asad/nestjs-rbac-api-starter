import { Injectable } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { randomUUID } from 'node:crypto';
import type { AppEnvironment } from '../../../config/env.validation.js';

export interface AccessClaims {
  readonly sub: string;
  readonly sid: string;
  readonly jti: string;
  readonly iat: number;
  readonly exp: number;
  readonly iss: string;
  readonly aud: string;
}

@Injectable()
export class TokenService {
  private readonly jwtService: JwtService;

  constructor(private readonly env: AppEnvironment) {
    this.jwtService = new JwtService({ secret: env.jwt.accessSecret });
  }

  async signAccessToken(userId: string, sessionId: string): Promise<string> {
    return this.jwtService.signAsync(
      { sub: userId, sid: sessionId, jti: randomUUID() },
      {
        expiresIn: this.env.accessToken.ttlSeconds,
        algorithm: 'HS256',
        issuer: this.env.jwt.issuer,
        audience: this.env.jwt.audience,
      },
    );
  }

  async verifyAccessToken(token: string): Promise<AccessClaims> {
    return this.jwtService.verifyAsync<AccessClaims>(token, {
      algorithms: ['HS256'],
      issuer: this.env.jwt.issuer,
      audience: this.env.jwt.audience,
    });
  }
}
