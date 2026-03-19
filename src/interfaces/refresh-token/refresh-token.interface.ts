/**
 * Minimum shape of a stored refresh token record.
 * Consumers may extend this with extra fields (e.g. device info, IP).
 */
export interface IRefreshToken {
  /** Stable record identifier. */
  id: string;
  /** Hashed token value (never store plaintext). */
  token: string;
  /** Owner of this token. */
  userId: string;
  /** Hard expiry timestamp. */
  expiresAt: Date;
}

/**
 * Port: refresh token persistence.
 *
 * Implement and pass as `refreshTokenRepository` to enable refresh-token
 * rotation.  If omitted, `AuthService.rotateRefreshToken()` will throw.
 */
export interface IRefreshTokenRepository<
  RT extends IRefreshToken = IRefreshToken,
> {
  /**
   * Persist a new hashed refresh token record.
   * Called immediately after issuing a token to the client.
   */
  create(data: Omit<RT, 'id'>): Promise<RT>;

  /**
   * Retrieve a valid (non-expired) token by its SHA-256 hash.
   * Returns `null` if not found or already consumed.
   */
  findByTokenHash(tokenHash: string): Promise<RT | null>;

  /**
   * Atomically find and delete a token by its hash in a single
   * database operation (e.g. `DELETE … RETURNING *` or a transaction).
   *
   * Returns the deleted record, or `null` if no matching row was found
   * (token unknown, already consumed, or belongs to a concurrent request).
   *
   * **Implementations must guarantee atomicity.** Two concurrent calls with
   * the same hash must each see at most one success; the second must return
   * `null`, never a duplicate row.
   */
  consumeByTokenHash(tokenHash: string): Promise<RT | null>;

  /** Delete a specific token (one-time-use enforcement). */
  deleteById(id: string): Promise<void>;

  /** Revoke all tokens for a user — "logout all devices". */
  deleteAllForUser(userId: string): Promise<void>;

  /** Optional housekeeping: purge expired rows from the store. */
  deleteExpired?(): Promise<void>;
}
