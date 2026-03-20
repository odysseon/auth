import type { ModuleMetadata, Type, FactoryProvider } from '@nestjs/common';
import type { JwtConfig } from './jwt-config.interface';
import type { GoogleOAuthConfig } from './google-oauth-config.interface';
import type { AuthUser, IUserRepository } from '../user-model';
import type { IRefreshToken, IRefreshTokenRepository } from '../refresh-token';

/**
 * The fully-resolved configuration object returned by `useFactory`.
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

/**
 * Async registration options — mirrors the standard NestJS
 * `*AsyncOptions` pattern so consumers can inject `ConfigService` etc.
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
   * when google is enabled).  Registered as a provider so it can itself
   * receive injected dependencies.
   */
  userRepository: Type<IUserRepository<User>>;

  /**
   * Class that implements `IRefreshTokenRepository`.
   * When omitted, refresh-token rotation is disabled and
   * `AuthService.rotateRefreshToken()` will throw.
   */
  refreshTokenRepository?: Type<IRefreshTokenRepository<RT>>;

  /**
   * Explicitly opt in to each authentication capability you need.
   * Only the listed capabilities will have their providers registered.
   */
  enabledCapabilities: Array<'credentials' | 'google'>;
}
