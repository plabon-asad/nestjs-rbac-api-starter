/** Client context captured from the incoming request for security-relevant logging. */
export interface RequestMeta {
  readonly ip?: string | undefined;
  readonly userAgent?: string | undefined;
}
