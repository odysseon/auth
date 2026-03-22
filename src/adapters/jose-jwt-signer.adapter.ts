import { Injectable } from '@nestjs/common';
import {
  SignJWT,
  jwtVerify,
  importPKCS8,
  importSPKI,
  errors as joseErrors,
} from 'jose';
import {
  type IJwtSigner,
  InvalidTokenError,
} from '../interfaces/ports/jwt-signer.port';
import type { JwtConfig, JwtPayload } from '../interfaces';
import { isSymmetric } from '../interfaces/configuration/jwt-config.interface';

/**
 * Default `IJwtSigner` adapter — wraps the **jose** library.
 *
 * jose is chosen as the default because it:
 * - Uses the Web Crypto API (hardware-acceleratable, FIPS-certifiable).
 * - Works in Node, Deno, Bun, and edge runtimes without modification.
 * - Has zero sub-dependencies.
 *
 * ### Swapping this adapter
 * Implement `IJwtSigner` and pass `jwtSigner: YourClass` to
 * `AuthModule.forRootAsync()`. Nothing else changes.
 *
 * ```ts
 * import * as jwt from 'jsonwebtoken';
 *
 * @Injectable()
 * export class JsonwebtokenSigner implements IJwtSigner {
 *   private secret!: string;
 *   async init(config: JwtConfig) { this.secret = (config as SymmetricJwtConfig).secret as string; }
 *   async sign(payload: JwtPayload, expiresIn: string | number) {
 *     return jwt.sign(payload, this.secret, { expiresIn });
 *   }
 *   async verify(token: string): Promise<JwtPayload> {
 *     return jwt.verify(token, this.secret) as JwtPayload;
 *   }
 * }
 * ```
 */
@Injectable()
export class JoseJwtSigner implements IJwtSigner {
  // In jose v5+, asymmetric keys are CryptoKey and symmetric keys are Uint8Array.
  private signingKey!: CryptoKey | Uint8Array;
  private verifyingKey!: CryptoKey | Uint8Array;
  private algorithm!: string;
  private issuer?: string;
  private audience?: string | string[];

  async init(config: JwtConfig): Promise<void> {
    const cfg = config.accessToken;
    this.algorithm = cfg.algorithm ?? (isSymmetric(config) ? 'HS256' : 'ES256');
    this.issuer = cfg.issuer;
    this.audience = cfg.audience;

    if (isSymmetric(config)) {
      const key =
        typeof config.secret === 'string'
          ? new TextEncoder().encode(config.secret)
          : (config.secret as Uint8Array);
      this.signingKey = key;
      this.verifyingKey = key;
    } else {
      // importPKCS8/importSPKI return Promise<CryptoKey> in jose v5+.
      this.signingKey = await importPKCS8(
        config.privateKey.toString(),
        this.algorithm,
      );
      this.verifyingKey = await importSPKI(
        config.publicKey.toString(),
        this.algorithm,
      );
    }
  }

  async sign(payload: JwtPayload, expiresIn: string | number): Promise<string> {
    const expiry = typeof expiresIn === 'number' ? `${expiresIn}s` : expiresIn;

    let builder = new SignJWT({ ...payload })
      .setProtectedHeader({ alg: this.algorithm })
      .setIssuedAt()
      .setExpirationTime(expiry);

    if (this.issuer) builder = builder.setIssuer(this.issuer);
    if (this.audience) builder = builder.setAudience(this.audience);

    return builder.sign(this.signingKey);
  }

  async verify(token: string): Promise<JwtPayload> {
    try {
      // jwtVerify accepts CryptoKey | Uint8Array directly.
      const { payload } = await jwtVerify(token, this.verifyingKey, {
        algorithms: [this.algorithm],
        ...(this.issuer ? { issuer: this.issuer } : {}),
        ...(this.audience ? { audience: this.audience } : {}),
      });

      return {
        sub: payload.sub as string,
        type: payload['type'] as 'access',
      };
    } catch (err) {
      // jose.errors.JOSEError is the base class for every token-level failure
      // jose can throw: JWTExpired, JWSSignatureVerificationFailed,
      // JWTClaimValidationFailed, JWTMalformed, JOSENotSupported, etc.
      // Infrastructure failures (TypeError, RangeError, network errors from a
      // KMS-backed key fetch, etc.) do NOT extend JOSEError and must propagate
      // unchanged so AuthService can surface them as 500s, not 401s.
      if (err instanceof joseErrors.JOSEError) {
        throw new InvalidTokenError(err.message);
      }
      throw err;
    }
  }
}
