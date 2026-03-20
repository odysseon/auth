/**
 * Port: password hashing.
 *
 * `AuthService` depends only on this interface for all password operations.
 * The default adapter uses `argon2id`. Swap it by implementing this interface
 * and passing the class to `AuthModule.forRootAsync({ passwordHasher: ... })`.
 *
 * ### Why is this a separate port from `ITokenHasher`?
 * Passwords are low-entropy and must be hashed with a slow, memory-hard
 * algorithm (argon2id, bcrypt, scrypt). Refresh tokens are already
 * high-entropy random byte strings and only need SHA-256. Conflating the
 * two would force every `IPasswordHasher` implementation to also handle
 * token generation, and every `ITokenHasher` to also support slow hashing.
 *
 * ### Swapping the default (Argon2PasswordHasher → bcrypt)
 * ```ts
 * import * as bcrypt from 'bcrypt';
 *
 * @Injectable()
 * export class BcryptPasswordHasher implements IPasswordHasher {
 *   async hash(password: string): Promise<string> {
 *     return bcrypt.hash(password, 12);
 *   }
 *   async verify(password: string, hash: string): Promise<boolean> {
 *     return bcrypt.compare(password, hash);
 *   }
 * }
 *
 * // In AuthModule.forRootAsync():
 * passwordHasher: BcryptPasswordHasher
 * ```
 */
export interface IPasswordHasher {
  /**
   * Produce a salted, slow hash of `password` suitable for long-term storage.
   *
   * Must use a memory-hard algorithm (argon2id, bcrypt, scrypt).
   * Never use a raw SHA family function here.
   */
  hash(password: string): Promise<string>;

  /**
   * Return `true` if `password` matches `hash`, `false` otherwise.
   *
   * Must not throw on a hash-format mismatch — return `false` instead.
   * Constant-time comparison is strongly recommended to resist timing attacks.
   */
  verify(password: string, hash: string): Promise<boolean>;
}
