import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { AUTH_CAPABILITIES, PORTS } from '../constants';
import type { JwtConfig, JwtPayload, RequestUser } from '../interfaces';
import type { IJwtSigner } from '../interfaces/ports/jwt-signer.port';
import { isSymmetric } from '../interfaces/configuration/jwt-config.interface';

/**
 * Passport strategy for Bearer token validation.
 *
 * `passport-jwt` handles extraction from the Authorization header and
 * initial signature verification (using the raw key material from JwtConfig).
 * After that, `validate()` runs the application-level checks via `IJwtSigner`
 * to enforce the `type: 'access'` discriminator.
 *
 * ### Why does the constructor still read JwtConfig directly?
 * `passport-jwt`'s `Strategy` constructor requires `secretOrKey` to be
 * passed synchronously — it does not support async key import. We pass the
 * raw PEM / secret here for Passport's own verification, and let `IJwtSigner`
 * handle the full verify path in `validate()`.
 *
 * If you swap to a signer that uses a different verification mechanism
 * (e.g. JWKS), override this strategy entirely and register it under the
 * 'jwt' Passport name.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy, 'jwt') {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    config: JwtConfig,

    @Inject(PORTS.JWT_SIGNER)
    private readonly jwtSigner: IJwtSigner,
  ) {
    // passport-jwt needs the raw key synchronously — the signer's async
    // init() has already run via AuthService.onModuleInit() at this point.
    const secretOrKey = isSymmetric(config) ? config.secret : config.publicKey;

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey,
      algorithms: config.accessToken.algorithm
        ? [config.accessToken.algorithm]
        : undefined,
      issuer: config.accessToken.issuer,
      audience: config.accessToken.audience,
    });
  }

  /**
   * Called by Passport after signature + expiry are verified.
   * We re-verify through IJwtSigner to enforce the `type` discriminator
   * and keep all payload validation in one place.
   */
  async validate(payload: JwtPayload): Promise<RequestUser> {
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
