import { Injectable } from '@nestjs/common';
import type { ITokenExtractor } from '../interfaces/ports/token-extractor.port';

/**
 * Extracts a JWT from a named HTTP cookie.
 *
 * Requires cookie-parser (or equivalent) middleware to be active in the
 * host application so that `request.cookies` is populated before the
 * guard runs.
 *
 * ```ts
 * // main.ts
 * import * as cookieParser from 'cookie-parser';
 * app.use(cookieParser());
 * ```
 *
 * ```ts
 * // AuthModule.forRootAsync()
 * tokenExtractor: new CookieTokenExtractor('access_token')
 * // — or via DI if you prefer a class provider:
 * { provide: PORTS.TOKEN_EXTRACTOR, useValue: new CookieTokenExtractor('access_token') }
 * ```
 */
@Injectable()
export class CookieTokenExtractor implements ITokenExtractor {
  constructor(private readonly cookieName: string) {}

  extract(request: unknown): string | null {
    const req = request as {
      cookies?: Record<string, string | undefined>;
    };
    return req?.cookies?.[this.cookieName] ?? null;
  }
}
