/**
 * Claims embedded in every access token issued by this module.
 * Intentionally minimal — `sub` is the only claim that identifies the user.
 */
export interface JwtPayload {
  /** Subject — the user's stable identifier. */
  sub: string;
  /**
   * Token type discriminator.  The JWT strategy rejects any token where
   * `type !== 'access'`, preventing refresh tokens from being used as
   * access tokens.
   */
  type: 'access';
}
