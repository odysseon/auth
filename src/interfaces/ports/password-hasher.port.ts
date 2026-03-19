/**
 * Port: password hashing.
 *
 * Defines what the auth module needs from a password hasher.
 * The default adapter ships with `argon2`, but you can provide any
 * implementation — bcrypt, scrypt, PBKDF2 — by satisfying this interface
 * and passing it as `passwordHasher` to `AuthModule.forRootAsync()`.
 *
 * @example Swap to bcrypt
 * ```ts
 * // bcrypt-password-hasher.adapter.ts
 * import * as bcrypt from 'bcrypt';
 *
 * @Injectable()
 * export class BcryptPasswordHasher implements IPasswordHasher {
 *   async hash(password: string) { return bcrypt.hash(password, 12); }
 *   async verify(password: string, hash: string) { return bcrypt.compare(password, hash); }
 * }
 *
 * // Then in AuthModule.forRootAsync():
 * passwordHasher: BcryptPasswordHasher
 * ```
 */
export interface IPasswordHasher {
  /**
   * Produce a salted hash of `password` suitable for long-term storage.
   * The implementation must use a slow, memory-hard algorithm (argon2id,
   * bcrypt, scrypt) — never a raw SHA family function.
   */
  hash(password: string): Promise<string>;

  /**
   * Return `true` if `password` matches `hash`, `false` otherwise.
   * Must never throw on a hash-format mismatch — return `false` instead.
   */
  verify(password: string, hash: string): Promise<boolean>;
}
