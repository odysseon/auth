import type { RequestUser } from './request-user.interface';

/**
 * Minimal request shape that carries a validated user identity.
 *
 * Intentionally framework-agnostic — this interface requires only the
 * `user` property that the auth module reads. It is structurally compatible
 * with Express's `Request`, Fastify's `FastifyRequest`, and any other
 * framework's request object.
 *
 * ```ts
 * // Express
 * @Get('me')
 * me(@Req() req: AuthenticatedRequest) { return req.user; }
 *
 * // Fastify
 * @Get('me')
 * me(@Req() req: AuthenticatedRequest) { return req.user; }
 *
 * // Plain Node.js (no framework)
 * const user: RequestUser = (req as AuthenticatedRequest).user;
 * ```
 */
export interface AuthenticatedRequest {
  user: RequestUser;
}
