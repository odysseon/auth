/**
 * Minimum shape of a stored refresh token record.
 * Consumers may extend this with extra fields (e.g. device fingerprint, IP).
 */
export interface IRefreshToken {
  /** Stable record identifier. */
  id: string;
  /** SHA-256 hash of the plaintext token. Never store the plaintext itself. */
  token: string;
  /** The user this token belongs to. */
  userId: string;
  /** Hard expiry — tokens found past this timestamp must be rejected. */
  expiresAt: Date;
}

/**
 * Port: refresh token persistence.
 *
 * Implement this in your infrastructure layer and pass the class to
 * `AuthModule.forRootAsync({ refreshTokenRepository: MyRepo })`.
 *
 * ### Why only these four methods?
 * Interface Segregation: every method here is called by `AuthService`.
 * No method exists as a "might be useful someday" addition.
 *
 * | Method                | Called by                          |
 * |-----------------------|------------------------------------|
 * | `create`              | `issueRefreshToken` (after login)  |
 * | `consumeByTokenHash`  | `rotateRefreshToken`               |
 * | `deleteAllForUser`    | `logout`                           |
 * | `deleteExpired`       | your own cleanup job (optional)    |
 */
export interface IRefreshTokenRepository<
  RT extends IRefreshToken = IRefreshToken,
> {
  /**
   * Persist a new hashed refresh token record.
   *
   * Called immediately after a token is issued to the client — the record
   * must exist before the response is sent so rotation can find it.
   */
  create(data: Omit<RT, 'id'>): Promise<RT>;

  /**
   * Atomically find **and delete** a token by its SHA-256 hash.
   *
   * This is the core of one-time-use enforcement. The operation must be
   * atomic — a single `DELETE … RETURNING *` (SQL) or a transaction —
   * so that two concurrent rotation requests with the same token each see
   * exactly one success. The second must receive `null`.
   *
   * Returns the deleted record on success, or `null` when:
   * - no record matches the hash (token unknown), or
   * - the record was already consumed by a concurrent request.
   */
  consumeByTokenHash(tokenHash: string): Promise<RT | null>;

  /**
   * Delete every refresh token belonging to `userId`.
   *
   * Called by `AuthService.logout()` to invalidate all sessions across
   * all devices simultaneously.
   */
  deleteAllForUser(userId: string): Promise<void>;

  /**
   * Purge expired records from the store.
   *
   * Optional — implement and call on a schedule (cron, queue job) to
   * prevent unbounded table growth. `AuthService` never calls this.
   */
  deleteExpired?(): Promise<void>;
}
