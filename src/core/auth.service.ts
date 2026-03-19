import {
  Injectable,
  Inject,
  Optional,
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  NotFoundException,
  Logger,
  OnModuleInit,
} from '@nestjs/common';
import { AUTH_CAPABILITIES, PORTS } from '../constants';
import type { IJwtSigner } from '../interfaces/ports/jwt-signer.port';
import type { IPasswordHasher } from '../interfaces/ports/password-hasher.port';
import type { ITokenHasher } from '../interfaces/ports/token-hasher.port';
import type {
  JwtConfig,
  AuthResponse,
  RequestUser,
  IUserRepository,
  IRefreshTokenRepository,
  IRefreshToken,
  AuthUser,
  LoginInput,
  RegistrationInput,
  PasswordChangeInput,
  PasswordSetInput,
} from '../interfaces';
import { validateJwtConfig } from '../interfaces/configuration/jwt-config.interface';

function parseDurationToSeconds(value: string | number): number {
  if (typeof value === 'number') return value;
  const m = value.match(/^(\d+)([smhdw])$/);
  // Groups 1 and 2 are guaranteed present when the regex matches.
  if (!m || !m[1] || !m[2])
    throw new Error(`[@odysseon/auth] Invalid duration format: "${value}"`);
  const n = parseInt(m[1], 10);
  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
  };
  return n * (multipliers[m[2]] ?? /* istanbul ignore next */ 1);
}

/**
 * The single use-case service for all authentication operations.
 *
 * All external library dependencies are injected through ports:
 * - `PORTS.JWT_SIGNER`      → `IJwtSigner`      (default: JoseJwtSigner)
 * - `PORTS.PASSWORD_HASHER` → `IPasswordHasher` (default: Argon2PasswordHasher)
 * - `PORTS.TOKEN_HASHER`    → `ITokenHasher`    (default: CryptoTokenHasher)
 *
 * Swap any of them by passing a different adapter class to `AuthModule.forRootAsync()`.
 * This service never imports a crypto or JWT library directly.
 *
 * ### Operations
 * | Method                 | Capability  | Description                              |
 * |------------------------|-------------|------------------------------------------|
 * | `loginWithCredentials` | credentials | Verify email + password, issue tokens    |
 * | `register`             | credentials | Create user, hash password, issue tokens |
 * | `handleGoogleCallback` | google      | Issue tokens after Passport OAuth flow   |
 * | `rotateRefreshToken`   | refresh     | Validate, consume, re-issue token pair   |
 * | `logout`               | refresh     | Revoke all refresh tokens for a user     |
 * | `changePassword`       | credentials | Change password (requires current)       |
 * | `setPassword`          | credentials | Force-set password (admin / reset)       |
 * | `verifyEmail`          | credentials | Mark email as verified                   |
 *
 * ### What this service does NOT do
 * - Authorisation (roles, permissions, policies)
 * - Email delivery
 * - Session management
 */
@Injectable()
export class AuthService implements OnModuleInit {
  private readonly logger = new Logger(AuthService.name);

  constructor(
    @Inject(AUTH_CAPABILITIES.JWT)
    private readonly jwtConfig: JwtConfig,

    @Inject(PORTS.JWT_SIGNER)
    private readonly jwtSigner: IJwtSigner,

    @Inject(PORTS.PASSWORD_HASHER)
    private readonly passwordHasher: IPasswordHasher,

    @Inject(PORTS.TOKEN_HASHER)
    private readonly tokenHasher: ITokenHasher,

    @Inject(PORTS.USER_REPOSITORY)
    private readonly userRepo: IUserRepository<Partial<AuthUser>>,

    @Optional()
    @Inject(PORTS.REFRESH_TOKEN_REPOSITORY)
    private readonly refreshTokenRepo: IRefreshTokenRepository<IRefreshToken> | null,
  ) {}

  async onModuleInit(): Promise<void> {
    validateJwtConfig(this.jwtConfig);
    await this.jwtSigner.init(this.jwtConfig);
    this.logger.log(
      `AuthService ready — JWT type: ${this.jwtConfig.type}, ` +
        `refresh tokens: ${this.refreshEnabled ? 'enabled' : 'disabled'}`,
    );
  }

  // ── Credentials: login ────────────────────────────────────────────────────

  async loginWithCredentials(input: LoginInput): Promise<AuthResponse> {
    const user = await this.userRepo.findByEmail(input.email);

    if (!user?.id) throw new UnauthorizedException('Invalid credentials');

    if (!('password' in user) || !user.password) {
      throw new UnauthorizedException(
        'This account was created via social login. Sign in with Google instead.',
      );
    }

    const valid = await this.passwordHasher.verify(
      input.password,
      user.password as string,
    );
    if (!valid) throw new UnauthorizedException('Invalid credentials');

    return this.buildAuthResponse(user.id);
  }

  // ── Credentials: register ─────────────────────────────────────────────────

  async register(input: RegistrationInput): Promise<AuthResponse> {
    const existing = await this.userRepo.findByEmail(input.email);
    if (existing) throw new ConflictException('Email already registered');

    const hashed = await this.passwordHasher.hash(input.password);
    const user = await this.userRepo.create({
      email: input.email,
      password: hashed,
    } as Partial<AuthUser>);

    if (!user?.id) throw new Error('User creation failed: no ID returned');

    this.logger.log(`New user registered: ${user.id}`);
    return this.buildAuthResponse(user.id);
  }

  // ── Google OAuth ──────────────────────────────────────────────────────────

  async handleGoogleCallback(requestUser: RequestUser): Promise<AuthResponse> {
    const user = await this.userRepo.findById(requestUser.userId);
    if (!user?.id)
      throw new UnauthorizedException('User not found after Google OAuth');
    return this.buildAuthResponse(user.id);
  }

  // ── Token rotation ────────────────────────────────────────────────────────

  async rotateRefreshToken(plainToken: string): Promise<AuthResponse> {
    this.assertRefreshEnabled();
    if (!plainToken) throw new BadRequestException('Refresh token is required');

    const tokenHash = this.tokenHasher.hash(plainToken);

    // Atomically find-and-delete so two concurrent requests with the same
    // token cannot both succeed and mint independent token pairs.
    const stored = await this.refreshTokenRepo!.consumeByTokenHash(tokenHash);

    if (!stored) {
      throw new UnauthorizedException(
        'Refresh token is invalid or has already been used',
      );
    }

    if (new Date() > stored.expiresAt) {
      // Token was consumed above; no further cleanup needed.
      throw new UnauthorizedException('Refresh token has expired');
    }

    const user = await this.userRepo.findById(stored.userId);
    if (!user?.id) throw new UnauthorizedException('User no longer exists');

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
    if (!user) throw new NotFoundException('User not found');

    if (!('password' in user) || !user.password) {
      throw new BadRequestException(
        'Password cannot be changed on OAuth-only accounts',
      );
    }

    const currentValid = await this.passwordHasher.verify(
      input.currentPassword,
      user.password as string,
    );
    if (!currentValid)
      throw new UnauthorizedException('Current password is incorrect');

    const isSame = await this.passwordHasher.verify(
      input.newPassword,
      user.password as string,
    );
    if (isSame) {
      throw new BadRequestException(
        'New password must differ from the current password',
      );
    }

    const hashed = await this.passwordHasher.hash(input.newPassword);
    await this.userRepo.update(input.userId, {
      password: hashed,
    } as Partial<AuthUser>);

    return { message: 'Password changed successfully' };
  }

  async setPassword(input: PasswordSetInput): Promise<{ message: string }> {
    const user = await this.userRepo.findById(input.userId);
    if (!user) throw new NotFoundException('User not found');

    const hashed = await this.passwordHasher.hash(input.newPassword);
    await this.userRepo.update(input.userId, {
      password: hashed,
    } as Partial<AuthUser>);

    return { message: 'Password set successfully' };
  }

  // ── Token verification (for custom guards / non-Passport setups) ──────────

  /**
   * Verify an access token and return its payload.
   *
   * Use this if you want to write a custom guard without Passport, or if you
   * are swapping `@nestjs/passport` for a different HTTP middleware layer.
   *
   * ```ts
   * // custom-auth.guard.ts
   * @Injectable()
   * export class CustomAuthGuard implements CanActivate {
   *   constructor(private readonly authService: AuthService) {}
   *
   *   async canActivate(ctx: ExecutionContext): Promise<boolean> {
   *     const req = ctx.switchToHttp().getRequest();
   *     const token = req.headers.authorization?.slice(7);
   *     if (!token) throw new UnauthorizedException();
   *     req.user = await this.authService.verifyAccessToken(token);
   *     return true;
   *   }
   * }
   * ```
   *
   * @throws `UnauthorizedException` for invalid, expired, or malformed tokens.
   */
  async verifyAccessToken(token: string): Promise<RequestUser> {
    try {
      const payload = await this.jwtSigner.verify(token);
      if (!payload.sub) throw new Error('missing sub');
      if (payload.type !== 'access') throw new Error('wrong token type');
      return { userId: payload.sub };
    } catch {
      throw new UnauthorizedException('Invalid or expired access token');
    }
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

    await this.refreshTokenRepo!.create({
      token: tokenHash,
      userId,
      expiresAt,
    } as Omit<IRefreshToken, 'id'>);

    return plainToken;
  }

  private get refreshEnabled(): boolean {
    return !!(this.refreshTokenRepo && this.jwtConfig.refreshToken);
  }

  private assertRefreshEnabled(): void {
    if (!this.refreshTokenRepo) {
      throw new BadRequestException(
        'Refresh tokens are not enabled. Provide a refreshTokenRepository ' +
          'in AuthModule.forRootAsync().',
      );
    }
    if (!this.jwtConfig.refreshToken) {
      throw new BadRequestException(
        'Refresh tokens are not enabled. Set jwt.refreshToken in the module ' +
          'config to activate refresh-token issuance.',
      );
    }
  }
}
