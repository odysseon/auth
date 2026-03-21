/**
 * Injection tokens used throughout the module.
 * Using Symbols ensures no accidental collision with host-app tokens.
 */

/** The resolved AuthModuleConfig object. */
export const AUTH_CONFIG = Symbol('AUTH_CONFIG');

/** Capability-specific config slices injected into sub-modules. */
export const AUTH_CAPABILITIES = Object.freeze({
  JWT: Symbol('JWT_CONFIG'),
  CREDENTIALS: Symbol('CREDENTIALS_CONFIG'),
  GOOGLE: Symbol('GOOGLE_CONFIG'),
});

/** Infrastructure port tokens — resolved to the caller-supplied adapters. */
export const PORTS = Object.freeze({
  // ── Caller-supplied (required / optional) ─────────────────────────────
  USER_REPOSITORY: Symbol('USER_REPOSITORY'),
  REFRESH_TOKEN_REPOSITORY: Symbol('REFRESH_TOKEN_REPOSITORY'),

  // ── Internal adapters (defaulted by AuthModule, swappable) ────────────
  /** IJwtSigner — defaults to JoseJwtSigner (jose). */
  JWT_SIGNER: Symbol('JWT_SIGNER'),
  /** IPasswordHasher — defaults to Argon2PasswordHasher (argon2). */
  PASSWORD_HASHER: Symbol('PASSWORD_HASHER'),
  /** ITokenHasher — defaults to CryptoTokenHasher (node:crypto). */
  TOKEN_HASHER: Symbol('TOKEN_HASHER'),
  /** ITokenExtractor — defaults to BearerTokenExtractor (Authorization header). */
  TOKEN_EXTRACTOR: Symbol('TOKEN_EXTRACTOR'),
  /** ILogger — defaults to ConsoleLogger (console.log / console.error). */
  LOGGER: Symbol('LOGGER'),
});
