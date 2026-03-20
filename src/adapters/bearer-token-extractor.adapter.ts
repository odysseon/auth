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
 */
@Injectable()
export class BearerTokenExtractor implements ITokenExtractor {
  extract(request: unknown): string | null {
    const req = request as { headers?: Record<string, string | undefined> };
    const header = req?.headers?.['authorization'];
    if (!header) return null;

    // RFC 7235 §2.1 — scheme is case-insensitive.
    const [scheme, token] = header.split(' ');
    if (!scheme || scheme.toLowerCase() !== 'bearer') return null;
    return token ?? null;
  }
}
