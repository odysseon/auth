/**
 * Typed error codes for every failure condition `AuthService` can produce.
 *
 * Consumers who use `AuthService` outside NestJS catch `AuthError` and map
 * these codes to whatever their framework expects. The NestJS adapter layer
 * (`AuthExceptionFilter`) maps them to HTTP responses automatically.
 */
export const AuthErrorCode = {
  // ── Credentials ───────────────────────────────────────────────────────────
  /** Email not found, or password does not match the stored hash. */
  INVALID_CREDENTIALS: 'INVALID_CREDENTIALS',
  /** Registration attempted with an email that already exists. */
  EMAIL_ALREADY_EXISTS: 'EMAIL_ALREADY_EXISTS',
  /** Password change/set requested on an OAuth-only account. */
  OAUTH_ACCOUNT_NO_PASSWORD: 'OAUTH_ACCOUNT_NO_PASSWORD',
  /** New password is identical to the current password. */
  PASSWORD_SAME_AS_OLD: 'PASSWORD_SAME_AS_OLD',
  /**
   * User record not found when a specific `userId` was required.
   * Thrown by: `changePassword`, `setPassword`, and `rotateRefreshToken`
   * (when the user referenced by the refresh token no longer exists).
   */
  USER_NOT_FOUND: 'USER_NOT_FOUND',

  // ── OAuth ─────────────────────────────────────────────────────────────────
  /**
   * `handleGoogleCallback` was called but the user record provisioned by
   * `GoogleStrategy.validate()` could not be found immediately after.
   * Indicates a race between user creation and the callback lookup.
   */
  OAUTH_USER_NOT_FOUND: 'OAUTH_USER_NOT_FOUND',

  // ── Refresh tokens ────────────────────────────────────────────────────────
  /** Token hash not found, or already consumed by a concurrent request. */
  REFRESH_TOKEN_INVALID: 'REFRESH_TOKEN_INVALID',
  /** Token was found but its `expiresAt` timestamp has passed. */
  REFRESH_TOKEN_EXPIRED: 'REFRESH_TOKEN_EXPIRED',
  /**
   * `rotateRefreshToken` was called but refresh tokens are not enabled
   * (missing repository or missing `jwt.refreshToken` config block).
   * This is a server misconfiguration, not a bad client request.
   */
  REFRESH_NOT_ENABLED: 'REFRESH_NOT_ENABLED',
} as const;

export type AuthErrorCode = (typeof AuthErrorCode)[keyof typeof AuthErrorCode];

/**
 * The single error class thrown by `AuthService`.
 *
 * Carries a typed `code` for programmatic handling and a human-readable
 * `message` for logs. Framework adapters map `code` to HTTP status codes
 * or gRPC status codes — the core never decides that.
 *
 * ```ts
 * // Plain Node.js / non-NestJS usage:
 * try {
 *   await authService.loginWithCredentials(input);
 * } catch (err) {
 *   if (err instanceof AuthError) {
 *     switch (err.code) {
 *       case AuthErrorCode.INVALID_CREDENTIALS: return reply.status(401).send();
 *       case AuthErrorCode.USER_NOT_FOUND:      return reply.status(404).send();
 *     }
 *   }
 *   throw err; // unexpected — re-throw
 * }
 * ```
 */
export class AuthError extends Error {
  constructor(
    public readonly code: AuthErrorCode,
    message: string,
  ) {
    super(message);
    this.name = 'AuthError';
    // Maintains correct instanceof chain in compiled JS.
    Object.setPrototypeOf(this, new.target.prototype);
  }
}
