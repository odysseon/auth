/**
 * Configuration passed to `passport-google-oauth20`'s Strategy constructor.
 * Aliased here so consumers import from one place.
 */
export interface GoogleOAuthConfig {
  clientID: string;
  clientSecret: string;
  callbackURL: string;
  /** Defaults to ['email', 'profile'] when omitted. */
  scope?: string[];
}
