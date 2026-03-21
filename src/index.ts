// ── Module & Service ──────────────────────────────────────────────────────
export { AuthModule } from './core/auth.module';
export type {
  AuthModuleAsyncOptions,
  AuthModuleAdapterOverrides,
} from './core/auth.module';
export { AuthService } from './core/auth.service';

// ── Error types ───────────────────────────────────────────────────────────
export { AuthError, AuthErrorCode } from './errors/auth-error';
export type { AuthErrorCode as AuthErrorCodeType } from './errors/auth-error';

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

// ── Full interface surface ─────────────────────────────────────────────────
export * from './interfaces';

// ── DI tokens ─────────────────────────────────────────────────────────────
export { AUTH_CAPABILITIES, PORTS, AUTH_CONFIG } from './constants';
