import { Injectable } from '@nestjs/common';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import type { KeyLike } from 'jose';
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
  // jose's KeyLike covers both CryptoKey (asymmetric) and Uint8Array (symmetric).
  private signingKey!: KeyLike | Uint8Array;
  private verifyingKey!: KeyLike | Uint8Array;
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
      // importPKCS8/importSPKI return Promise<KeyLike> — store as KeyLike.
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
      // jwtVerify accepts KeyLike | Uint8Array directly — no cast needed.
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
      // jose throws JWSInvalidError, JWTExpired, JWTClaimValidationFailed etc.
      // for token-level failures. Wrap them as InvalidTokenError so
      // AuthService.verifyAccessToken() can distinguish them from
      // infrastructure errors (which should not map to 401).
      throw new InvalidTokenError((err as Error).message);
    }
  }
}
