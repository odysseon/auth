// Only export the types consumers actually need to use the library.
// SymmetricJwtConfig, AsymmetricJwtConfig, TokenSignOptions, isSymmetric,
// isAsymmetric, and validateJwtConfig are internal implementation details
// — adapters and the module import them directly by path.
export type { JwtConfig, RefreshTokenConfig } from './jwt-config.interface';
export { parseDurationToSeconds } from './jwt-config.interface';
export type { GoogleOAuthConfig } from './google-oauth-config.interface';
export type { AuthModuleConfig } from './auth-module-config.interface';
