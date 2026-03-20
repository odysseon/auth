/**
 * Port: opaque token hashing and generation.
 *
 * Used exclusively for the refresh token lifecycle:
 * - `generate` produces the plaintext token sent to the client.
 * - `hash` produces the value stored in the database (never plaintext).
 *
 * The default adapter uses Node's built-in `crypto` module with no extra
 * dependencies. Swap it by implementing this interface and passing the class
 * to `AuthModule.forRootAsync({ tokenHasher: ... })`.
 *
 * ### Why is this separate from `IPasswordHasher`?
 * Refresh tokens are already high-entropy (256-bit random) before hashing.
 * SHA-256 is fast, deterministic, and sufficient here — a slow password
 * hashing function would add latency on every token rotation with no
 * security benefit. Keeping the two ports separate lets each carry exactly
 * the contract its consumer needs.
 *
 * ### Swapping to a KMS-backed implementation
 * ```ts
 * @Injectable()
 * export class KmsTokenHasher implements ITokenHasher {
 *   hash(token: string): string {
 *     return kmsClient.hmac(token); // deterministic HMAC via KMS
 *   }
 *   generate(bytes = 32): string {
 *     return kmsClient.random(bytes);
 *   }
 * }
 *
 * // In AuthModule.forRootAsync():
 * tokenHasher: KmsTokenHasher
 * ```
 */
export interface ITokenHasher {
  /**
   * Hash a high-entropy opaque token for database storage.
   *
   * SHA-256 (or equivalent one-way function) is appropriate here.
   * Do **not** use a slow password-hashing algorithm — this is called on
   * every token rotation and latency matters.
   *
   * @returns A deterministic, hex-encoded hash string.
   */
  hash(token: string): string;

  /**
   * Generate a cryptographically secure random plaintext token.
   *
   * This is the value returned to the client and must have enough entropy
   * to make brute-force infeasible. The default is 32 bytes (256 bits).
   *
   * @param bytes Number of random bytes. Default: 32. Do not go below 16.
   * @returns Hex-encoded plaintext (length = bytes × 2).
   */
  generate(bytes?: number): string;
}
