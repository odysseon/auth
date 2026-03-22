import type { JwtConfig, JwtPayload } from '../index';

/**
 * Thrown by `IJwtSigner.verify()` when a token is cryptographically invalid,
 * expired, or malformed — as opposed to an infrastructure failure (network,
 * KMS timeout, etc.).
 *
 * `AuthService.verifyAccessToken()` catches this specific class and maps it
 * to `AuthErrorCode.ACCESS_TOKEN_INVALID`. Any other error thrown by
 * `verify()` is treated as unexpected and re-thrown without wrapping, so
 * infrastructure failures surface as 500s rather than 401s.
 *
 * Every `IJwtSigner` implementation **must** throw `InvalidTokenError` (or a
 * subclass) for token-level failures and let infrastructure errors propagate
 * as-is.
 */
export class InvalidTokenError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidTokenError';
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Port: JWT signing and verification.
 *
 * `AuthService` and `JwtStrategy` depend only on this interface.
 * Neither ever imports `jose`, `jsonwebtoken`, or any other JWT library.
 * Swap the underlying library by providing a different adapter class.
 *
 * ### Swapping the default (JoseJwtSigner → jsonwebtoken)
 * ```ts
 * import * as jwt from 'jsonwebtoken';
 *
 * @Injectable()
 * export class JsonwebtokenSigner implements IJwtSigner {
 *   private secret!: string;
 *
 *   async init(config: JwtConfig): Promise<void> {
 *     this.secret = (config as SymmetricJwtConfig).secret as string;
 *   }
 *
 *   async sign(payload: JwtPayload, expiresIn: string | number): Promise<string> {
 *     return jwt.sign(payload, this.secret, { expiresIn });
 *   }
 *
 *   async verify(token: string): Promise<JwtPayload> {
 *     try {
 *       return jwt.verify(token, this.secret) as JwtPayload;
 *     } catch (err) {
 *       // Wrap token-level errors as InvalidTokenError so AuthService can
 *       // distinguish them from infrastructure failures.
 *       throw new InvalidTokenError((err as Error).message);
 *     }
 *   }
 * }
 *
 * // In AuthModule.forRootAsync():
 * jwtSigner: JsonwebtokenSigner
 * ```
 *
 * ### Why `init()` instead of constructor injection?
 * Key material may require async I/O (reading PEM files, calling a KMS).
 * `init()` is called once during `AuthService.init()` at application boot,
 * keeping constructors synchronous and side-effect free.
 */
export interface IJwtSigner {
  /**
   * Initialise the signer with key material derived from `JwtConfig`.
   * Called once at application boot, before any request is served.
   * If this throws, the application will fail to start — which is correct.
   */
  init(config: JwtConfig): Promise<void>;

  /**
   * Sign a payload and return a compact JWT string.
   *
   * @param payload   Claims to embed. Must include `sub` and `type: 'access'`.
   * @param expiresIn Duration string (`'15m'`) or seconds as a number.
   */
  sign(payload: JwtPayload, expiresIn: string | number): Promise<string>;

  /**
   * Verify a token's signature, expiry, and any configured claims (issuer,
   * audience). Return the decoded payload on success.
   *
   * **Do not validate `type` here** — that check belongs in `AuthService`
   * and `JwtStrategy` so that the discriminator is enforced consistently
   * regardless of which adapter is in use.
   *
   * **Error contract:**
   * - Throw `InvalidTokenError` for token-level failures (bad signature,
   *   expired, malformed, wrong issuer/audience).
   * - Let infrastructure errors (KMS timeout, network failure) propagate
   *   as-is so `AuthService` can distinguish them from auth failures.
   */
  verify(token: string): Promise<JwtPayload>;
}
