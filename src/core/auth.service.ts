import { Injectable, Inject, Optional } from '@nestjs/common';
import { AUTH_CAPABILITIES, PORTS } from '../constants';
import {
  type IJwtSigner,
  InvalidTokenError,
} from '../interfaces/ports/jwt-signer.port';
import type { IPasswordHasher } from '../interfaces/ports/password-hasher.port';
import type { ITokenHasher } from '../interfaces/ports/token-hasher.port';
import type { ILogger } from '../interfaces/ports/logger.port';
import type {
  JwtConfig,
  AuthResponse,
  RequestUser,
  IUserRepository,
  IRefreshTokenRepository,
  IRefreshToken,
  LoginInput,
  RegistrationInput,
  PasswordChangeInput,
  PasswordSetInput,
} from '../interfaces';
import type { AuthUser } from '../interfaces/user-model/user.interface';
import { parseDurationToSeconds } from '../interfaces/configuration/jwt-config.interface';
import { validateJwtConfig } from '../interfaces/configuration/jwt-config.interface';
import { AuthError, AuthErrorCode } from '../errors/auth-error';

// ── Internal input types ───────────────────────────────────────────────────
// These replace the `as Partial<AuthUser>` casts that were suppressing the
// type system at repository boundaries. Each type represents exactly what
// AuthService passes to the repository — no more, no less.

type UserCreateInput = Pick<AuthUser, 'email'> &
  Partial<Pick<AuthUser, 'password'>>;
type GoogleUserCreateInput = Pick<AuthUser, 'email' | 'googleId'>;
type GoogleUserLinkInput = Pick<AuthUser, 'googleId'>;
type PasswordUpdateInput = Pick<AuthUser, 'password'>;

/**
 * The single use-case service for all authentication operations.
 *
 * ### Framework independence
 * `AuthService` has no dependency on any HTTP framework. All external
 * dependencies are injected through ports. It throws `AuthError` with typed
 * `AuthErrorCode` values — never HTTP-specific exceptions. Framework adapters
 * (e.g. `AuthExceptionFilter` for NestJS) map those codes to HTTP responses.
 *
 * This means `AuthService` can be used directly in:
 * - NestJS (Express or Fastify) via `AuthModule`
 * - Plain Express / Fastify without NestJS
 * - Queue workers, Lambda functions, CLI tools, gRPC services
 *
 * ### Ports injected
 * | Token                            | Port                       | Default adapter        |
 * |----------------------------------|----------------------------|------------------------|
 * | `PORTS.JWT_SIGNER`               | `IJwtSigner`               | `JoseJwtSigner`        |
 * | `PORTS.PASSWORD_HASHER`          | `IPasswordHasher`          | `Argon2PasswordHasher` |
 * | `PORTS.TOKEN_HASHER`             | `ITokenHasher`             | `CryptoTokenHasher`    |
 * | `PORTS.LOGGER`                   | `ILogger`                  | `ConsoleLogger`        |
 * | `PORTS.USER_REPOSITORY`          | `IUserRepository`          | consumer-supplied      |
 * | `PORTS.REFRESH_TOKEN_REPOSITORY` | `IRefreshTokenRepository`  | consumer-supplied (optional) |
 *
 * ### Operations
 * | Method                 | Capability  | Description                              |
 * |------------------------|-------------|------------------------------------------|
 * | `loginWithCredentials` | credentials | Verify email + password, issue tokens    |
 * | `register`             | credentials | Hash password, create user, issue tokens |
 * | `handleGoogleCallback` | google      | Issue tokens after Passport OAuth flow   |
 * | `rotateRefreshToken`   | refresh     | Atomic consume + re-issue (one-time use) |
 * | `logout`               | refresh     | Revoke all refresh tokens for a user     |
 * | `verifyAccessToken`    | any         | Verify a token (for custom guards)       |
 * | `changePassword`       | credentials | Change password (requires current)       |
 * | `setPassword`          | credentials | Force-set password (admin / reset flow)  |
 *
 * ### What this service does NOT do
 * - Authorisation (roles, permissions, resource policies)
 * - Email delivery or verification
 * - Session management
 * - HTTP response formatting
 */
@Injectable()
export class AuthService {
  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly jwtConfig: JwtConfig,

    @Inject(PORTS.JWT_SIGNER)
    private readonly jwtSigner: IJwtSigner,

    @Inject(PORTS.PASSWORD_HASHER)
    private readonly passwordHasher: IPasswordHasher,

    @Inject(PORTS.TOKEN_HASHER)
    private readonly tokenHasher: ITokenHasher,

    @Inject(PORTS.LOGGER)
    private readonly logger: ILogger,

    @Inject(PORTS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository<Partial<AuthUser>>,

    @Optional()
    @Inject(PORTS.REFRESH_TOKEN_REPOSITORY)
    private readonly refreshTokenRepo: IRefreshTokenRepository<IRefreshToken> | null,
  ) {}

  /**
   * Validates config and initialises the JWT signer.
   * Call this once at startup before serving any requests.
   * `AuthModule` calls it automatically via `AuthInitializer`.
   */
  async init(): Promise<void> {
    validateJwtConfig(this.jwtConfig);
    await this.jwtSigner.init(this.jwtConfig);
    this.logger.log(
      `ready — JWT type: ${this.jwtConfig.type}, ` +
        `refresh tokens: ${this.refreshEnabled ? 'enabled' : 'disabled'}`,
    );
  }

  // ── Credentials: login ────────────────────────────────────────────────────

  async loginWithCredentials(input: LoginInput): Promise<AuthResponse> {
    const user = await this.userRepo.findByEmail(input.email);

    if (!user?.id) {
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Invalid credentials',
      );
    }

    if (!('password' in user) || !user.password) {
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'This account was created via social login. Sign in with Google instead.',
      );
    }

    const valid = await this.passwordHasher.verify(
      input.password,
      user.password as string,
    );
    if (!valid) {
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Invalid credentials',
      );
    }

    return this.buildAuthResponse(user.id);
  }

  // ── Credentials: register ─────────────────────────────────────────────────

  async register(input: RegistrationInput): Promise<AuthResponse> {
    const existing = await this.userRepo.findByEmail(input.email);
    if (existing) {
      throw new AuthError(
        AuthErrorCode.EMAIL_ALREADY_EXISTS,
        'Email already registered',
      );
    }

    const hashed = await this.passwordHasher.hash(input.password);
    const createInput: UserCreateInput = {
      email: input.email,
      password: hashed,
    };
    const user = await this.userRepo.create(createInput);

    if (!user?.id) throw new Error('User creation failed: no ID returned');

    this.logger.log(`New user registered: ${user.id}`);
    return this.buildAuthResponse(user.id);
  }

  // ── Google OAuth ──────────────────────────────────────────────────────────

  async handleGoogleCallback(requestUser: RequestUser): Promise<AuthResponse> {
    const user = await this.userRepo.findById(requestUser.userId);
    if (!user?.id) {
      throw new AuthError(
        AuthErrorCode.OAUTH_USER_NOT_FOUND,
        'User not found after Google OAuth',
      );
    }
    return this.buildAuthResponse(user.id);
  }

  // ── Token rotation ────────────────────────────────────────────────────────

  async rotateRefreshToken(plainToken: string): Promise<AuthResponse> {
    this.assertRefreshEnabled();
    if (!plainToken) {
      throw new AuthError(
        AuthErrorCode.REFRESH_TOKEN_INVALID,
        'Refresh token is required',
      );
    }

    const tokenHash = this.tokenHasher.hash(plainToken);

    // Atomically find-and-delete so two concurrent requests with the same
    // token cannot both succeed and mint independent token pairs.
    const stored = await this.refreshTokenRepo!.consumeByTokenHash(tokenHash);

    if (!stored) {
      throw new AuthError(
        AuthErrorCode.REFRESH_TOKEN_INVALID,
        'Refresh token is invalid or has already been used',
      );
    }

    if (new Date() > stored.expiresAt) {
      // Token was consumed above; no further cleanup needed.
      throw new AuthError(
        AuthErrorCode.REFRESH_TOKEN_EXPIRED,
        'Refresh token has expired',
      );
    }

    const user = await this.userRepo.findById(stored.userId);
    if (!user?.id) {
      throw new AuthError(
        AuthErrorCode.USER_NOT_FOUND,
        'User no longer exists',
      );
    }

    return this.buildAuthResponse(user.id);
  }

  // ── Logout ────────────────────────────────────────────────────────────────

  async logout(userId: string): Promise<void> {
    if (this.refreshTokenRepo) {
      await this.refreshTokenRepo.deleteAllForUser(userId);
    }
    this.logger.log(`User ${userId} logged out — all refresh tokens revoked`);
  }

  // ── Password management ───────────────────────────────────────────────────

  async changePassword(
    input: PasswordChangeInput,
  ): Promise<{ message: string }> {
    const user = await this.userRepo.findById(input.userId);
    if (!user) {
      throw new AuthError(AuthErrorCode.USER_NOT_FOUND, 'User not found');
    }

    if (!('password' in user) || !user.password) {
      throw new AuthError(
        AuthErrorCode.OAUTH_ACCOUNT_NO_PASSWORD,
        'Password cannot be changed on OAuth-only accounts',
      );
    }

    const currentValid = await this.passwordHasher.verify(
      input.currentPassword,
      user.password as string,
    );
    if (!currentValid) {
      throw new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Current password is incorrect',
      );
    }

    const isSame = await this.passwordHasher.verify(
      input.newPassword,
      user.password as string,
    );
    if (isSame) {
      throw new AuthError(
        AuthErrorCode.PASSWORD_SAME_AS_OLD,
        'New password must differ from the current password',
      );
    }

    const hashed = await this.passwordHasher.hash(input.newPassword);
    const updateInput: PasswordUpdateInput = { password: hashed };
    await this.userRepo.update(input.userId, updateInput);

    return { message: 'Password changed successfully' };
  }

  async setPassword(input: PasswordSetInput): Promise<{ message: string }> {
    const user = await this.userRepo.findById(input.userId);
    if (!user) {
      throw new AuthError(AuthErrorCode.USER_NOT_FOUND, 'User not found');
    }

    const hashed = await this.passwordHasher.hash(input.newPassword);
    const updateInput: PasswordUpdateInput = { password: hashed };
    await this.userRepo.update(input.userId, updateInput);

    return { message: 'Password set successfully' };
  }

  // ── Token verification (for custom guards / non-Passport setups) ──────────

  /**
   * Verify an access token and return its payload.
   *
   * Use this to build framework-agnostic guards, or when replacing Passport
   * with a different middleware layer. The token must have been issued with
   * `type: 'access'` — refresh tokens are rejected.
   *
   * ```ts
   * // Fastify hook (no NestJS):
   * fastify.addHook('preHandler', async (request) => {
   *   const token = request.headers.authorization?.slice(7);
   *   if (!token) throw fastify.httpErrors.unauthorized();
   *   request.user = await authService.verifyAccessToken(token);
   * });
   * ```
   *
   * @throws `AuthError` with code `ACCESS_TOKEN_INVALID` for invalid, expired,
   *         or malformed tokens, and for tokens with the wrong `type` claim.
   *         Infrastructure failures (KMS timeout, network error) from the
   *         `IJwtSigner` adapter are re-thrown without wrapping.
   */
  async verifyAccessToken(token: string): Promise<RequestUser> {
    let payload;
    try {
      payload = await this.jwtSigner.verify(token);
    } catch (err) {
      if (err instanceof InvalidTokenError) {
        throw new AuthError(
          AuthErrorCode.ACCESS_TOKEN_INVALID,
          'Invalid or expired access token',
        );
      }
      // Infrastructure failure — re-throw so it surfaces as a 500, not a 401.
      throw err;
    }

    if (!payload.sub) {
      throw new AuthError(
        AuthErrorCode.ACCESS_TOKEN_INVALID,
        'Invalid token: missing sub claim',
      );
    }
    if (payload.type !== 'access') {
      throw new AuthError(
        AuthErrorCode.ACCESS_TOKEN_INVALID,
        'Invalid token type: expected an access token',
      );
    }

    return { userId: payload.sub };
  }

  // ── Internal helpers ──────────────────────────────────────────────────────

  private async buildAuthResponse(userId: string): Promise<AuthResponse> {
    const [accessToken, refreshToken] = await Promise.all([
      this.signAccessToken(userId),
      this.refreshEnabled
        ? this.issueRefreshToken(userId)
        : Promise.resolve(undefined),
    ]);

    return {
      user: { userId },
      accessToken,
      ...(refreshToken ? { refreshToken } : {}),
    };
  }

  private signAccessToken(userId: string): Promise<string> {
    const { expiresIn } = this.jwtConfig.accessToken;
    return this.jwtSigner.sign({ sub: userId, type: 'access' }, expiresIn);
  }

  private async issueRefreshToken(userId: string): Promise<string> {
    const rtConfig = this.jwtConfig.refreshToken!;
    const plainToken = this.tokenHasher.generate(rtConfig.tokenLength ?? 32);
    const tokenHash = this.tokenHasher.hash(plainToken);
    const ttlSeconds = parseDurationToSeconds(rtConfig.expiresIn);
    const expiresAt = new Date(Date.now() + ttlSeconds * 1000);

    const createInput: Omit<IRefreshToken, 'id'> = {
      token: tokenHash,
      userId,
      expiresAt,
    };
    await this.refreshTokenRepo!.create(createInput);

    return plainToken;
  }

  private get refreshEnabled(): boolean {
    return !!(this.refreshTokenRepo && this.jwtConfig.refreshToken);
  }

  private assertRefreshEnabled(): void {
    if (!this.refreshTokenRepo || !this.jwtConfig.refreshToken) {
      throw new AuthError(
        AuthErrorCode.REFRESH_NOT_ENABLED,
        'Refresh tokens are not enabled. Provide a refreshTokenRepository ' +
          'and a jwt.refreshToken config block in AuthModule.forRootAsync().',
      );
    }
  }
}

// ── Named exports for GoogleStrategy (internal use only) ──────────────────
// GoogleStrategy calls userRepo.create and userRepo.update with the same
// narrow input shapes AuthService uses. Exporting them avoids duplicating
// the types in the strategy file.
export type { GoogleUserCreateInput, GoogleUserLinkInput };
