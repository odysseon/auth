import type { JwtConfig, JwtPayload } from '../index';

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
 *     // Extract key material once at startup.
 *     this.secret = (config as SymmetricJwtConfig).secret as string;
 *   }
 *
 *   async sign(payload: JwtPayload, expiresIn: string | number): Promise<string> {
 *     return jwt.sign(payload, this.secret, { expiresIn });
 *   }
 *
 *   async verify(token: string): Promise<JwtPayload> {
 *     return jwt.verify(token, this.secret) as JwtPayload;
 *   }
 * }
 *
 * // In AuthModule.forRootAsync():
 * jwtSigner: JsonwebtokenSigner
 * ```
 *
 * ### Why `init()` instead of constructor injection?
 * Key material may require async I/O (reading PEM files, calling a KMS).
 * `init()` is called once during `AuthService.onModuleInit()`, keeping
 * NestJS constructors synchronous and side-effect free.
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
   * @throws Any error on invalid signature, expiry, or claim mismatch.
   *         `AuthService` will wrap thrown errors in `UnauthorizedException`.
   */
  verify(token: string): Promise<JwtPayload>;
}
