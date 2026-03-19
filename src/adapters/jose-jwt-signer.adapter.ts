import { Injectable } from '@nestjs/common';
import { SignJWT, jwtVerify, importPKCS8, importSPKI } from 'jose';
import type { IJwtSigner } from '../interfaces/ports/jwt-signer.port';
import type { JwtConfig, JwtPayload } from '../interfaces';
import { isSymmetric } from '../interfaces/configuration/jwt-config.interface';

/**
 * Default `IJwtSigner` adapter — uses the **jose** library.
 *
 * jose is chosen as the default because it:
 * - Uses the Web Crypto API (hardware-acceleratable, FIPS-certifiable).
 * - Works in Node, Deno, Bun, and edge runtimes without modification.
 * - Has zero sub-dependencies.
 *
 * ### Swapping this adapter
 * Pass `jwtSigner: YourSignerClass` to `AuthModule.forRootAsync()` and
 * implement `IJwtSigner`.  The rest of the module is completely unaffected.
 *
 * ```ts
 * // jsonwebtoken-signer.adapter.ts
 * import * as jwt from 'jsonwebtoken';
 *
 * @Injectable()
 * export class JsonwebtokenSigner implements IJwtSigner {
 *   private secret!: string;
 *
 *   async init(config: JwtConfig) {
 *     this.secret = (config as SymmetricJwtConfig).secret as string;
 *   }
 *
 *   async sign(payload: JwtPayload, expiresIn: string | number) {
 *     return jwt.sign(payload, this.secret, { expiresIn });
 *   }
 *
 *   async verify(token: string): Promise<JwtPayload> {
 *     return jwt.verify(token, this.secret) as JwtPayload;
 *   }
 * }
 * ```
 */
@Injectable()
export class JoseJwtSigner implements IJwtSigner {
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
      this.signingKey = await importPKCS8(config.privateKey.toString(), this.algorithm);
      this.verifyingKey = await importSPKI(config.publicKey.toString(), this.algorithm);
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

    return builder.sign(this.signingKey as Parameters<typeof builder.sign>[0]);
  }

  async verify(token: string): Promise<JwtPayload> {
    const { payload } = await jwtVerify(token, this.verifyingKey as Parameters<typeof jwtVerify>[1], {
      algorithms: [this.algorithm],
      ...(this.issuer ? { issuer: this.issuer } : {}),
      ...(this.audience ? { audience: this.audience } : {}),
    });

    return {
      sub: payload.sub as string,
      type: payload['type'] as 'access',
    };
  }
}
