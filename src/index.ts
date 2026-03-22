// ── Module & Service ──────────────────────────────────────────────────────
export { AuthModule } from './core/auth.module';
export type {
  AuthModuleAsyncOptions,
  AuthModuleAdapterOverrides,
} from './core/auth.module';
export { AuthService } from './core/auth.service';

// ── Error types ───────────────────────────────────────────────────────────
export { AuthError, AuthErrorCode } from './errors/auth-error';

// ── NestJS HTTP adapter ───────────────────────────────────────────────────
export { AuthExceptionFilter } from './filters/auth-exception.filter';

// ── Guards ────────────────────────────────────────────────────────────────
export { JwtAuthGuard } from './guards/jwt-auth.guard';
export { GoogleOAuthGuard } from './guards/google-oauth.guard';

// ── Decorators ────────────────────────────────────────────────────────────
export { CurrentUser } from './decorators/current-user.decorator';
export { Public, IS_PUBLIC_KEY } from './decorators/public.decorator';

// ── Default adapters (swappable — see interfaces/ports/ for the contracts) ─
export { JoseJwtSigner } from './adapters/jose-jwt-signer.adapter';
export { Argon2PasswordHasher } from './adapters/argon2-password-hasher.adapter';
export { CryptoTokenHasher } from './adapters/crypto-token-hasher.adapter';
export { BearerTokenExtractor } from './adapters/bearer-token-extractor.adapter';
export { CookieTokenExtractor } from './adapters/cookie-token-extractor.adapter';
export { QueryParamTokenExtractor } from './adapters/query-param-token-extractor.adapter';
export { ConsoleLogger } from './adapters/console-logger.adapter';

// ── Port interfaces ────────────────────────────────────────────────────────
// Implement these in your application to provide repositories and swap adapters.
export type { IJwtSigner } from './interfaces/ports/jwt-signer.port';
export { InvalidTokenError } from './interfaces/ports/jwt-signer.port';
export type { IPasswordHasher } from './interfaces/ports/password-hasher.port';
export type { ITokenHasher } from './interfaces/ports/token-hasher.port';
export type { ITokenExtractor } from './interfaces/ports/token-extractor.port';
export type { ILogger } from './interfaces/ports/logger.port';
export type {
  IUserRepository,
  IGoogleUserRepository,
} from './interfaces/user-model/user-repository.interface';
export type {
  IRefreshToken,
  IRefreshTokenRepository,
} from './interfaces/refresh-token/refresh-token.interface';

// ── Domain types ──────────────────────────────────────────────────────────
// Config, response shapes, operation inputs, and user model types that
// consumers reference in controllers, DTOs, and repository implementations.
export type {
  JwtConfig,
  RefreshTokenConfig,
} from './interfaces/configuration/jwt-config.interface';
export { parseDurationToSeconds } from './interfaces/configuration/jwt-config.interface';
export type { GoogleOAuthConfig } from './interfaces/configuration/google-oauth-config.interface';
export type { AuthModuleConfig } from './interfaces/configuration/auth-module-config.interface';
export type {
  AuthUser,
  BaseUser,
  CredentialsUser,
  GoogleUser,
} from './interfaces/user-model/user.interface';
export type { RequestUser } from './interfaces/user-model/request-user.interface';
export type { AuthenticatedRequest } from './interfaces/user-model/authenticated-request.interface';
export type {
  AuthResponse,
  TokenPair,
} from './interfaces/authentication/auth-response.interface';
export type { JwtPayload } from './interfaces/authentication/jwt-payload.interface';
export type {
  LoginInput,
  RegistrationInput,
  PasswordChangeInput,
  PasswordSetInput,
} from './interfaces/operation-contracts/index';

// ── DI tokens — for test overrides only ───────────────────────────────────
// Use these with overrideProvider() in unit tests.
// AUTH_CONFIG and AUTH_CAPABILITIES are internal module wiring — not exported.
export { PORTS } from './constants';
