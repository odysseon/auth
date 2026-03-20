import { DynamicModule, Global, Module, Provider, Type } from '@nestjs/common';
import { PassportModule } from '@nestjs/passport';
import { AUTH_CONFIG, AUTH_CAPABILITIES, PORTS } from '../constants';
import { AuthService } from './auth.service';
import { JwtStrategy } from '../strategies/jwt.strategy';
import { GoogleStrategy } from '../strategies/google.strategy';
import { JwtAuthGuard } from '../guards/jwt-auth.guard';
import { GoogleOAuthGuard } from '../guards/google-oauth.guard';
import { JoseJwtSigner } from '../adapters/jose-jwt-signer.adapter';
import { Argon2PasswordHasher } from '../adapters/argon2-password-hasher.adapter';
import { CryptoTokenHasher } from '../adapters/crypto-token-hasher.adapter';
import type { IJwtSigner } from '../interfaces/ports/jwt-signer.port';
import type { IPasswordHasher } from '../interfaces/ports/password-hasher.port';
import type { ITokenHasher } from '../interfaces/ports/token-hasher.port';
import type {
  AuthModuleAsyncOptions,
  AuthModuleConfig,
  AuthUser,
} from '../interfaces';
import type { IRefreshToken } from '../interfaces/refresh-token';
import { validateJwtConfig } from '../interfaces/configuration/jwt-config.interface';

/**
 * Extend the async options with optional adapter overrides.
 * Each defaults to the bundled adapter if omitted.
 */
export interface AuthModuleAdapterOverrides {
  /**
   * Custom JWT signer adapter.
   * Default: `JoseJwtSigner` (jose library — Web Crypto, zero deps).
   * Swap to: jsonwebtoken, fast-jwt, or any `IJwtSigner` implementation.
   */
  jwtSigner?: Type<IJwtSigner>;

  /**
   * Custom password hasher adapter.
   * Default: `Argon2PasswordHasher` (argon2id — OWASP recommended).
   * Swap to: bcrypt, scrypt, PBKDF2, or any `IPasswordHasher` implementation.
   */
  passwordHasher?: Type<IPasswordHasher>;

  /**
   * Custom token hasher adapter.
   * Default: `CryptoTokenHasher` (Node built-in crypto — no extra deps).
   * Swap to: a KMS-backed, HSM-backed, or any `ITokenHasher` implementation.
   */
  tokenHasher?: Type<ITokenHasher>;
}

/**
 * The root authentication module.
 *
 * Register once at the top of your module tree with `forRootAsync()`.
 * Decorated `@Global()` — every module in the application can inject
 * `AuthService`, `JwtAuthGuard`, and `GoogleOAuthGuard` without re-importing.
 *
 * ### Default adapters (all swappable)
 * | Port               | Default adapter        | Swap via                  |
 * |--------------------|------------------------|---------------------------|
 * | `IJwtSigner`       | `JoseJwtSigner`        | `jwtSigner: MyAdapter`    |
 * | `IPasswordHasher`  | `Argon2PasswordHasher` | `passwordHasher: MyAdapter` |
 * | `ITokenHasher`     | `CryptoTokenHasher`    | `tokenHasher: MyAdapter`  |
 *
 * @example
 * ```ts
 * AuthModule.forRootAsync({
 *   imports: [ConfigModule],
 *   inject:  [ConfigService],
 *   useFactory: (cfg: ConfigService) => ({
 *     jwt: {
 *       type: 'asymmetric',
 *       privateKey:   cfg.get('JWT_PRIVATE_KEY'),
 *       publicKey:    cfg.get('JWT_PUBLIC_KEY'),
 *       accessToken:  { expiresIn: '15m', algorithm: 'ES256' },
 *       refreshToken: { expiresIn: '7d' },
 *     },
 *     google: {
 *       clientID:     cfg.get('GOOGLE_CLIENT_ID'),
 *       clientSecret: cfg.get('GOOGLE_CLIENT_SECRET'),
 *       callbackURL:  cfg.get('GOOGLE_CALLBACK_URL'),
 *     },
 *   }),
 *   userRepository:         UserRepository,
 *   refreshTokenRepository: RefreshTokenRepository,
 *   enabledCapabilities:    ['credentials', 'google'],
 *
 *   // Optional — swap any default adapter:
 *   // jwtSigner:      JsonwebtokenSigner,
 *   // passwordHasher: BcryptPasswordHasher,
 *   // tokenHasher:    KmsTokenHasher,
 * })
 * ```
 */
@Global()
@Module({})
export class AuthModule {
  static forRootAsync<
    User extends Partial<AuthUser> = Partial<AuthUser>,
    RT extends IRefreshToken = IRefreshToken,
  >(
    options: AuthModuleAsyncOptions<User, RT> & AuthModuleAdapterOverrides,
  ): DynamicModule {
    // ── Config ─────────────────────────────────────────────────────────────
    const configProvider: Provider = {
      provide: AUTH_CONFIG,
      useFactory: options.useFactory,
      inject: options.inject ?? [],
    };

    const jwtCapabilityProvider: Provider = {
      provide: AUTH_CAPABILITIES.JWT,
      useFactory: (cfg: AuthModuleConfig) => {
        validateJwtConfig(cfg.jwt);
        return cfg.jwt;
      },
      inject: [AUTH_CONFIG],
    };

    const googleCapabilityProvider: Provider = {
      provide: AUTH_CAPABILITIES.GOOGLE,
      useFactory: (cfg: AuthModuleConfig) =>
        options.enabledCapabilities.includes('google')
          ? (cfg.google ?? null)
          : null,
      inject: [AUTH_CONFIG],
    };

    // ── Caller-supplied repository ports ───────────────────────────────────
    const userRepoProvider: Provider = {
      provide: PORTS.USER_REPOSITORY,
      useClass: options.userRepository,
    };

    // ── Adapter ports — defaults with opt-in overrides ─────────────────────
    const jwtSignerClass = options.jwtSigner ?? JoseJwtSigner;
    const passwordHasherClass = options.passwordHasher ?? Argon2PasswordHasher;
    const tokenHasherClass = options.tokenHasher ?? CryptoTokenHasher;

    const jwtSignerProvider: Provider = {
      provide: PORTS.JWT_SIGNER,
      useClass: jwtSignerClass,
    };
    const passwordHasherProvider: Provider = {
      provide: PORTS.PASSWORD_HASHER,
      useClass: passwordHasherClass,
    };
    const tokenHasherProvider: Provider = {
      provide: PORTS.TOKEN_HASHER,
      useClass: tokenHasherClass,
    };

    // ── Assemble ───────────────────────────────────────────────────────────
    const providers: Provider[] = [
      configProvider,
      jwtCapabilityProvider,
      googleCapabilityProvider,
      userRepoProvider,
      jwtSignerProvider,
      passwordHasherProvider,
      tokenHasherProvider,
      AuthService,
      JwtStrategy,
      JwtAuthGuard,
    ];

    const moduleExports: Array<string | symbol | Provider> = [
      AuthService,
      JwtAuthGuard,
      // Expose adapter tokens so advanced consumers can inject them directly.
      PORTS.JWT_SIGNER,
      PORTS.PASSWORD_HASHER,
      PORTS.TOKEN_HASHER,
    ];

    // ── Refresh token repository (optional) ───────────────────────────────
    if (options.refreshTokenRepository) {
      // Validate that jwt.refreshToken config is also present; a repository
      // without the config block would cause a silent runtime failure when
      // AuthService tries to read rtConfig.expiresIn.
      const configValidationProvider: Provider = {
        provide: 'REFRESH_TOKEN_CONFIG_GUARD',
        useFactory: (cfg: AuthModuleConfig) => {
          if (!cfg.jwt.refreshToken) {
            throw new Error(
              '[@odysseon/auth] refreshTokenRepository is provided but ' +
                'jwt.refreshToken config is missing. Either add a ' +
                'jwt.refreshToken block or remove refreshTokenRepository.',
            );
          }
          return true;
        },
        inject: [AUTH_CONFIG],
      };
      providers.push(configValidationProvider);
      providers.push({
        provide: PORTS.REFRESH_TOKEN_REPOSITORY,
        useClass: options.refreshTokenRepository,
      });
      moduleExports.push(PORTS.REFRESH_TOKEN_REPOSITORY);
    }

    // ── Google capability (optional) ──────────────────────────────────────
    if (options.enabledCapabilities.includes('google')) {
      providers.push(GoogleStrategy, GoogleOAuthGuard);
      moduleExports.push(GoogleOAuthGuard);
    }

    return {
      module: AuthModule,
      global: true,
      imports: [PassportModule, ...(options.imports ?? [])],
      providers,
      exports: moduleExports,
    };
  }
}
