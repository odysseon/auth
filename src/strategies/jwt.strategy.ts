import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-jwt';
import type { Algorithm } from 'jsonwebtoken';
import { AUTH_CAPABILITIES, PORTS } from '../constants';
import type { JwtConfig, JwtPayload, RequestUser } from '../interfaces';
import type { ITokenExtractor } from '../interfaces/ports/token-extractor.port';
import { isSymmetric } from '../interfaces/configuration/jwt-config.interface';

/**
 * Passport strategy for JWT validation.
 *
 * This class is the **Passport adapter boundary**. It is the one place in
 * the module where coupling to `passport-jwt` is intentional and contained.
 * Everything above this layer (AuthService, guards, decorators) is
 * framework-agnostic by design.
 *
 * ### Token extraction
 * Token extraction is delegated to the `ITokenExtractor` port, injected via
 * `PORTS.TOKEN_EXTRACTOR`. `AuthModule` defaults this to
 * `BearerTokenExtractor` (`Authorization: Bearer <token>`). Pass a different
 * adapter to `AuthModule.forRootAsync({ tokenExtractor: MyExtractor })` to
 * read tokens from a cookie, a query parameter, or any custom source without
 * touching this class.
 *
 * ### Constraint: synchronous key requirement
 * `passport-jwt`'s Strategy constructor requires `secretOrKey` synchronously.
 * We satisfy this by reading the raw key material from `JwtConfig` directly.
 * The full async key lifecycle (import, caching) is handled by `IJwtSigner`
 * inside `AuthService`. This class only validates claims in `validate()`.
 *
 * ### Swapping Passport entirely
 * If you replace Passport with a different HTTP middleware, implement a new
 * guard that calls `authService.verifyAccessToken(token)` and remove this
 * strategy and `JwtAuthGuard`. The rest of the module is unaffected —
 * `AuthService` depends on no HTTP framework.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    config: JwtConfig,
    @Inject(PORTS.TOKEN_EXTRACTOR)
    tokenExtractor: ITokenExtractor,
  ) {
    const secretOrKey = isSymmetric(config) ? config.secret : config.publicKey;

    // passport-jwt's Algorithm[] is the jsonwebtoken union literal type.
    // Our TokenSignOptions.algorithm is string? to stay library-agnostic at
    // the port level. We narrow to Algorithm[] here at the adapter boundary.
    const algorithms = config.accessToken.algorithm
      ? [config.accessToken.algorithm as Algorithm]
      : undefined;

    super({
      jwtFromRequest: (req: unknown) => tokenExtractor.extract(req),
      ignoreExpiration: false,
      secretOrKey,
      algorithms,
      issuer: config.accessToken.issuer,
      audience: config.accessToken.audience,
    });
  }

  /**
   * Called by Passport after signature + expiry verification passes.
   * Enforces the `type: 'access'` discriminator so refresh tokens cannot
   * be presented as access tokens.
   */
  validate(payload: JwtPayload): RequestUser {
    if (!payload.sub) {
      throw new UnauthorizedException('Invalid token: missing sub claim');
    }
    if (payload.type !== 'access') {
      throw new UnauthorizedException(
        'Invalid token type: expected an access token, got refresh token',
      );
    }
    return { userId: payload.sub };
  }
}
