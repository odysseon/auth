import {
  DynamicModule,
  Global,
  Module,
  Provider,
  Type,
  OnModuleInit,
  Inject,
} from '@nestjs/common';
import type { ModuleMetadata, FactoryProvider } from '@nestjs/common';
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
import { BearerTokenExtractor } from '../adapters/bearer-token-extractor.adapter';
import { ConsoleLogger } from '../adapters/console-logger.adapter';
import type { IJwtSigner } from '../interfaces/ports/jwt-signer.port';
import type { IPasswordHasher } from '../interfaces/ports/password-hasher.port';
import type { ITokenHasher } from '../interfaces/ports/token-hasher.port';
import type { ITokenExtractor } from '../interfaces/ports/token-extractor.port';
import type { ILogger } from '../interfaces/ports/logger.port';
import type { AuthModuleConfig } from '../interfaces/configuration/auth-module-config.interface';
import type { AuthUser, IUserRepository } from '../interfaces/user-model';
import type {
  IRefreshToken,
  IRefreshTokenRepository,
} from '../interfaces/refresh-token';
import { validateJwtConfig } from '../interfaces/configuration/jwt-config.interface';

// ── NestJS wiring types (live here, not in the interface layer) ───────────

/**
 * Async registration options for `AuthModule.forRootAsync()`.
 *
 * Mirrors the standard NestJS `*AsyncOptions` pattern so consumers can
 * inject `ConfigService` or any other provider into `useFactory`.
 *
 * This type lives alongside `forRootAsync()` in the module file — it is a
 * NestJS wiring concern, not a domain contract, and therefore does not belong
 * in `interfaces/configuration/`.
 */
export interface AuthModuleAsyncOptions<
  User extends Partial<AuthUser> = Partial<AuthUser>,
  RT extends IRefreshToken = IRefreshToken,
>
  extends
    Pick<ModuleMetadata, 'imports'>,
    Pick<FactoryProvider<AuthModuleConfig>, 'useFactory' | 'inject'> {
  /**
   * Class that implements `IUserRepository` (or `IGoogleUserRepository`
   * when google is enabled). Registered as a provider so it can receive
   * its own injected dependencies.
   */
  userRepository: Type<IUserRepository<User>>;

  /**
   * Class that implements `IRefreshTokenRepository`.
   * When omitted, refresh-token rotation is disabled and
   * `AuthService.rotateRefreshToken()` will throw `AuthError` with
   * code `REFRESH_NOT_ENABLED`.
   */
  refreshTokenRepository?: Type<IRefreshTokenRepository<RT>>;

  /**
   * Explicitly opt in to each authentication capability you need.
   * Only the listed capabilities will have their providers registered.
   */
  enabledCapabilities: Array<'credentials' | 'google'>;
}

/**
 * Optional adapter overrides — each defaults to the bundled implementation.
 */
export interface AuthModuleAdapterOverrides {
  /**
   * Custom JWT signer adapter.
   * Default: `JoseJwtSigner` (jose — Web Crypto, zero deps).
   */
  jwtSigner?: Type<IJwtSigner>;

  /**
   * Custom password hasher adapter.
   * Default: `Argon2PasswordHasher` (argon2id — OWASP recommended).
   */
  passwordHasher?: Type<IPasswordHasher>;

  /**
   * Custom token hasher adapter.
   * Default: `CryptoTokenHasher` (node:crypto — no extra deps).
   */
  tokenHasher?: Type<ITokenHasher>;

  /**
   * Custom token extractor adapter.
   * Default: `BearerTokenExtractor` (`Authorization: Bearer <token>`).
   * Accepts a class or a pre-built instance for extractors that require
   * constructor arguments (e.g. `new CookieTokenExtractor('access_token')`).
   */
  tokenExtractor?: Type<ITokenExtractor> | ITokenExtractor;

  /**
   * Custom logger adapter.
   * Default: `ConsoleLogger` (console.log / console.error).
   * Swap to get NestJS structured logging, Pino, Winston, etc.
   *
   * @example
   * ```ts
   * // NestJS Logger
   * @Injectable()
   * class NestJsLogger implements ILogger {
   *   private readonly l = new Logger('AuthService');
   *   log(msg: string)               { this.l.log(msg); }
   *   error(msg: string, ctx?: unknown) { this.l.error(msg, ctx); }
   * }
   * // AuthModule.forRootAsync({ logger: NestJsLogger, ... })
   * ```
   */
  logger?: Type<ILogger>;
}

// ── Internal OnModuleInit wrapper ─────────────────────────────────────────

/**
 * Internal NestJS lifecycle hook that calls `AuthService.init()` at startup.
 *
 * `AuthService` itself does not implement `OnModuleInit` — it is a plain
 * class with no framework lifecycle coupling. This wrapper lives in the
 * module file (the NestJS adapter layer) and is the only place that ties
 * the startup sequence to NestJS.
 */
@Global()
@Module({})
class AuthInitializer implements OnModuleInit {
  constructor(
    @Inject(AuthService)
    private readonly authService: AuthService,
  ) {}

  async onModuleInit(): Promise<void> {
    await this.authService.init();
  }
}

// ── AuthModule ────────────────────────────────────────────────────────────

/**
 * The root authentication module.
 *
 * Register once at the top of your module tree with `forRootAsync()`.
 * Decorated `@Global()` — every module in the application can inject
 * `AuthService`, `JwtAuthGuard`, and `GoogleOAuthGuard` without re-importing.
 *
 * ### Default adapters (all swappable)
 * | Port               | Default adapter        | Swap via            |
 * |--------------------|------------------------|---------------------|
 * | `IJwtSigner`       | `JoseJwtSigner`        | `jwtSigner:`        |
 * | `IPasswordHasher`  | `Argon2PasswordHasher` | `passwordHasher:`   |
 * | `ITokenHasher`     | `CryptoTokenHasher`    | `tokenHasher:`      |
 * | `ITokenExtractor`  | `BearerTokenExtractor` | `tokenExtractor:`   |
 * | `ILogger`          | `ConsoleLogger`        | `logger:`           |
 *
 * ### Error handling
 * `AuthService` throws `AuthError` with typed `AuthErrorCode` values.
 * Register `AuthExceptionFilter` to map these to HTTP responses:
 *
 * ```ts
 * // app.module.ts
 * providers: [{ provide: APP_FILTER, useClass: AuthExceptionFilter }]
 * ```
 *
 * @example
 * ```ts
 * AuthModule.forRootAsync({
 *   imports:  [ConfigModule],
 *   inject:   [ConfigService],
 *   useFactory: (cfg: ConfigService) => ({
 *     jwt: {
 *       type:         'asymmetric',
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
    // ── Config ───────────────────────────────────────────────────────────
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

    // ── Caller-supplied repository ────────────────────────────────────────
    const userRepoProvider: Provider = {
      provide: PORTS.USER_REPOSITORY,
      useClass: options.userRepository,
    };

    // ── Swappable adapter ports ───────────────────────────────────────────
    const jwtSignerProvider: Provider = {
      provide: PORTS.JWT_SIGNER,
      useClass: options.jwtSigner ?? JoseJwtSigner,
    };
    const passwordHasherProvider: Provider = {
      provide: PORTS.PASSWORD_HASHER,
      useClass: options.passwordHasher ?? Argon2PasswordHasher,
    };
    const tokenHasherProvider: Provider = {
      provide: PORTS.TOKEN_HASHER,
      useClass: options.tokenHasher ?? CryptoTokenHasher,
    };

    // tokenExtractor accepts a class or a pre-built instance.
    const tokenExtractorProvider: Provider =
      options.tokenExtractor == null
        ? { provide: PORTS.TOKEN_EXTRACTOR, useClass: BearerTokenExtractor }
        : typeof options.tokenExtractor === 'function'
          ? { provide: PORTS.TOKEN_EXTRACTOR, useClass: options.tokenExtractor }
          : {
              provide: PORTS.TOKEN_EXTRACTOR,
              useValue: options.tokenExtractor,
            };

    const loggerProvider: Provider = {
      provide: PORTS.LOGGER,
      useClass: options.logger ?? ConsoleLogger,
    };

    // ── Assemble ─────────────────────────────────────────────────────────
    const providers: Provider[] = [
      configProvider,
      jwtCapabilityProvider,
      googleCapabilityProvider,
      userRepoProvider,
      jwtSignerProvider,
      passwordHasherProvider,
      tokenHasherProvider,
      tokenExtractorProvider,
      loggerProvider,
      AuthService,
      AuthInitializer,
      JwtStrategy,
      JwtAuthGuard,
    ];

    const moduleExports: Array<string | symbol | Provider> = [
      AuthService,
      JwtAuthGuard,
      PORTS.JWT_SIGNER,
      PORTS.PASSWORD_HASHER,
      PORTS.TOKEN_HASHER,
      PORTS.TOKEN_EXTRACTOR,
      PORTS.LOGGER,
    ];

    // ── Refresh token repository (optional) ───────────────────────────────
    if (options.refreshTokenRepository) {
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
