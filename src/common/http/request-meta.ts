import type { Request } from 'express';
import type { RequestMeta } from '../interfaces/request-meta.interface.js';

export function requestMeta(req: Request): RequestMeta {
  return { ip: req.ip, userAgent: req.headers['user-agent'] };
}
