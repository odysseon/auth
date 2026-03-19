import type { JwtConfig, JwtPayload } from '../index';

/**
 * Port: JWT signing and verification.
 *
 * `AuthService` and `JwtStrategy` depend only on this interface — they
 * never import `jose`, `jsonwebtoken`, or any other JWT library directly.
 * Swap the underlying library by providing a different adapter.
 *
 * @example Swap to jsonwebtoken
 * ```ts
 * import * as jwt from 'jsonwebtoken';
 *
 * @Injectable()
 * export class JsonwebtokenSigner implements IJwtSigner {
 *   async init(config: JwtConfig) { ... }
 *   async sign(payload, expiresIn) { return jwt.sign(payload, this.secret, { expiresIn }); }
 *   async verify(token) { return jwt.verify(token, this.secret) as JwtPayload; }
 *   getVerifyingKey() { return this.secret; }
 * }
 * ```
 *
 * ### Why `init()` instead of constructor injection?
 * Key material from `JwtConfig` may need async I/O (e.g. loading a PEM
 * file, calling a KMS). `init()` is called once from `AuthModule` during
 * the `onApplicationBootstrap` lifecycle, keeping constructors synchronous
 * and side-effect free.
 */
export interface IJwtSigner {
  /**
   * Initialise the signer with key material from `JwtConfig`.
   * Called once at application boot before any request is served.
   */
  init(config: JwtConfig): Promise<void>;

  /**
   * Sign a JWT payload and return the compact token string.
   *
   * @param payload  Claims to embed. Must include `sub` and `type`.
   * @param expiresIn  Duration string ('15m') or seconds as a number.
   */
  sign(payload: JwtPayload, expiresIn: string | number): Promise<string>;

  /**
   * Verify a token's signature and expiry.
   *
   * @returns The decoded payload on success.
   * @throws  Any error on invalid signature, expiry, or claim mismatch.
   *          `AuthService` will wrap this in an `UnauthorizedException`.
   */
  verify(token: string): Promise<JwtPayload>;
}
