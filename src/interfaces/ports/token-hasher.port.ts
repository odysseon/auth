/**
 * Port: opaque token hashing and generation.
 *
 * Covers the two operations needed for refresh-token lifecycle:
 * generating a cryptographically secure plaintext token, and hashing it
 * for safe storage.
 *
 * The default adapter uses Node's built-in `crypto` module (no extra
 * dependency), but you can swap to any implementation — e.g. one backed
 * by a HSM or KMS — without touching core logic.
 *
 * Note: this port is intentionally separate from `IPasswordHasher`.
 * Refresh tokens are already high-entropy random values; they do not need
 * a slow hash function. Using SHA-256 here is correct and intentional.
 */
export interface ITokenHasher {
  /**
   * Hash a high-entropy opaque token for storage.
   * SHA-256 is appropriate — do NOT use a password hashing algorithm here.
   *
   * @returns Hex-encoded hash string.
   */
  hash(token: string): string;

  /**
   * Generate a cryptographically secure random token.
   *
   * @param bytes Number of random bytes. Default 32 → 256 bits of entropy.
   * @returns Hex-encoded plaintext token (length = bytes * 2).
   */
  generate(bytes?: number): string;
}
