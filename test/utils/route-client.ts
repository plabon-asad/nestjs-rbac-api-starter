import type { INestApplication } from '@nestjs/common';
import request from 'supertest';

export type RouteMethod = 'get' | 'post' | 'patch' | 'put' | 'delete';

export interface RouteClient {
  readonly get: (path: string) => request.Test;
  readonly post: (path: string) => request.Test;
  readonly patch: (path: string) => request.Test;
  readonly put: (path: string) => request.Test;
  readonly delete: (path: string) => request.Test;
}

/** Bearer-authenticated HTTP client for e2e specs; reads the token lazily so rotated tokens work. */
export function routeClient(app: INestApplication, token: string | (() => string)): RouteClient {
  const call = (method: RouteMethod, path: string): request.Test => {
    const sender = request(app.getHttpServer())[method](path);
    return sender.set('Authorization', `Bearer ${typeof token === 'function' ? token() : token}`);
  };

  return {
    get: (path) => call('get', path),
    post: (path) => call('post', path),
    patch: (path) => call('patch', path),
    put: (path) => call('put', path),
    delete: (path) => call('delete', path),
  };
}
