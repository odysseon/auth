// ── Module & Service ──────────────────────────────────────────────────────
export { AuthModule } from './core/auth.module';
export type { AuthModuleAdapterOverrides } from './core/auth.module';
export { AuthService } from './core/auth.service';

// ── Guards ────────────────────────────────────────────────────────────────
export { JwtAuthGuard } from './guards/jwt-auth.guard';
export { GoogleOAuthGuard } from './guards/google-oauth.guard';

// ── Decorators ────────────────────────────────────────────────────────────
export { CurrentUser } from './decorators/current-user.decorator';
export { Public, IS_PUBLIC_KEY } from './decorators/public.decorator';

// ── Default adapters (swappable — see interfaces/ports/ for the contracts) ─
// Import these to extend or reference default implementations.
// Pass your own class to AuthModule.forRootAsync() to replace any of them.
export { JoseJwtSigner } from './adapters/jose-jwt-signer.adapter';
export { Argon2PasswordHasher } from './adapters/argon2-password-hasher.adapter';
export { CryptoTokenHasher } from './adapters/crypto-token-hasher.adapter';

// ── Full interface surface ─────────────────────────────────────────────────
// IUserRepository, IGoogleUserRepository, IRefreshTokenRepository
//   → implement in your infrastructure layer (ORM adapters etc.)
// IJwtSigner, IPasswordHasher, ITokenHasher
//   → implement to swap out default external library adapters
export * from './interfaces';

// ── DI tokens (for testing overrides and advanced wiring) ─────────────────
export { AUTH_CAPABILITIES, PORTS, AUTH_CONFIG } from './constants';
