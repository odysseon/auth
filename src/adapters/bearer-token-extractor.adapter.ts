import { Injectable } from '@nestjs/common';
import type { ITokenExtractor } from '../interfaces/ports/token-extractor.port';

/**
 * Extracts a JWT from the `Authorization: Bearer <token>` header.
 *
 * This is the **default** token extractor registered by `AuthModule`.
 * It replicates the behaviour of `passport-jwt`'s
 * `ExtractJwt.fromAuthHeaderAsBearerToken()` without importing that helper
 * directly, keeping the strategy decoupled from `passport-jwt` internals.
 *
 * Header format (case-insensitive scheme per RFC 7235):
 * ```
 * Authorization: Bearer eyJhbGciOiJFUzI1NiJ9...
 * ```
 *
 * Defensive handling:
 * - If the header value is an array (some frameworks forward multi-value
 *   headers as arrays), the first entry is used.
 * - Non-string values and missing headers both return `null`.
 * - An empty or whitespace-only token (e.g. `"Bearer "`) returns `null`.
 */
@Injectable()
export class BearerTokenExtractor implements ITokenExtractor {
  // Matches "Bearer <token>" case-insensitively; captures everything after
  // the required whitespace so tokens containing internal spaces are rejected
  // at the JWT layer, not here.
  private static readonly BEARER_RE = /^Bearer\s+(\S+)$/i;

  extract(request: unknown): string | null {
    const req = request as {
      headers?: Record<string, string | string[] | undefined>;
    };

    let raw = req?.headers?.['authorization'];
    if (!raw) return null;

    // Some HTTP server / proxy implementations forward repeated headers as
    // an array. Use only the first value and discard the rest.
    if (Array.isArray(raw)) {
      raw = raw[0];
    }

    if (typeof raw !== 'string') return null;

    const match = BearerTokenExtractor.BEARER_RE.exec(raw);
    return match?.[1] ?? null;
  }
}
