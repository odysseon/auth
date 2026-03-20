import { Injectable } from '@nestjs/common';
import type { ITokenExtractor } from '../interfaces/ports/token-extractor.port';

/**
 * Extracts a JWT from a URL query parameter.
 *
 * Suitable for use-cases where headers are inconvenient — e.g. WebSocket
 * handshakes, server-sent events, or file-download links. For standard API
 * requests, prefer `BearerTokenExtractor` (the default).
 *
 * **Security note:** Query parameters are logged by most HTTP servers and
 * proxies. Use this extractor only when the transport is HTTPS and you
 * have reviewed the logging posture of every component in the request path.
 *
 * ```ts
 * // AuthModule.forRootAsync()
 * tokenExtractor: new QueryParamTokenExtractor('token')
 * // → reads ?token=<jwt> from the URL
 * ```
 */
@Injectable()
export class QueryParamTokenExtractor implements ITokenExtractor {
  constructor(private readonly paramName: string) {}

  extract(request: unknown): string | null {
    const req = request as {
      query?: Record<string, string | string[] | undefined>;
    };
    const value = req?.query?.[this.paramName];
    if (!value) return null;
    // query values may be string[] when the param appears multiple times.
    return Array.isArray(value) ? (value[0] ?? null) : value;
  }
}
