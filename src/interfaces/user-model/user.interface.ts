/**
 * Minimum fields every user entity must expose to the auth module.
 */
export interface BaseUser {
  /** Stable, opaque user identifier (UUID or similar). */
  id: string;
  email: string;
  isEmailVerified: boolean;
}

/** Fields present when the user can authenticate with a password. */
export interface CredentialsUser {
  password?: string | null;
}

/** Fields present when the user has a linked Google account. */
export interface GoogleUser {
  googleId?: string | null;
}

/**
 * Full intersection type.  Consumers intersect only the slices they need:
 *
 * ```ts
 * class User implements BaseUser & GoogleUser { ... }
 * ```
 */
export type AuthUser = BaseUser & CredentialsUser & GoogleUser;
