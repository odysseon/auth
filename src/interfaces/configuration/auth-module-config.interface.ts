import type { JwtConfig } from './jwt-config.interface';
import type { GoogleOAuthConfig } from './google-oauth-config.interface';

/**
 * The fully-resolved configuration object returned by `useFactory`.
 *
 * This is a pure TypeScript type — no framework imports.
 * `AuthModuleAsyncOptions` (the NestJS wiring type) lives in `auth.module.ts`
 * alongside `forRootAsync()`, where framework coupling is intentional.
 */
export interface AuthModuleConfig {
  /** JWT signing/verification configuration. Required. */
  jwt: JwtConfig;
  /**
   * Google OAuth credentials.
   * Required when `'google'` is listed in `enabledCapabilities`.
   */
  google?: GoogleOAuthConfig;
}
