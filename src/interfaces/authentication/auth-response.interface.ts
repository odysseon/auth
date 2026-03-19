import type { RequestUser } from '../user-model';

/**
 * Tokens returned after any successful authentication operation.
 * `refreshToken` is absent when refresh tokens are not configured.
 */
export interface TokenPair {
  accessToken: string;
  refreshToken?: string;
}

/**
 * Standard response envelope for all auth endpoints.
 * Wraps the token pair with the minimal user identity.
 */
export interface AuthResponse extends TokenPair {
  user: RequestUser;
}
