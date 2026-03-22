import { Test } from '@nestjs/testing';
import { AuthService } from './auth.service';
import { AuthError, AuthErrorCode } from '../errors/auth-error';
import { InvalidTokenError } from '../interfaces/ports/jwt-signer.port';
import { AUTH_CAPABILITIES, PORTS } from '../constants';
import type { IJwtSigner } from '../interfaces/ports/jwt-signer.port';
import type { IPasswordHasher } from '../interfaces/ports/password-hasher.port';
import type { ITokenHasher } from '../interfaces/ports/token-hasher.port';
import type { ILogger } from '../interfaces/ports/logger.port';
import type { IUserRepository } from '../interfaces/user-model/user-repository.interface';
import type { IRefreshTokenRepository } from '../interfaces/refresh-token/refresh-token.interface';
import type { JwtConfig } from '../interfaces/configuration/jwt-config.interface';
import type { AuthUser } from '../interfaces/user-model/user.interface';

// ── Shared fixtures ───────────────────────────────────────────────────────────

const JWT_CONFIG: JwtConfig = {
  type: 'symmetric',
  secret: 'test-secret',
  accessToken: { expiresIn: '15m' },
  refreshToken: { expiresIn: '7d' },
};

const MOCK_USER = {
  id: 'user-1',
  email: 'test@example.com',
  password: 'hashed-password',
  googleId: null,
};

// ── Mock factories ────────────────────────────────────────────────────────────

function makeMockJwtSigner(): jest.Mocked<IJwtSigner> {
  return {
    init: jest.fn().mockResolvedValue(undefined),
    sign: jest.fn().mockResolvedValue('mock-access-token'),
    verify: jest.fn().mockResolvedValue({ sub: 'user-1', type: 'access' }),
  };
}

function makeMockPasswordHasher(): jest.Mocked<IPasswordHasher> {
  return {
    hash: jest.fn().mockResolvedValue('hashed-password'),
    verify: jest.fn().mockResolvedValue(true),
  };
}

function makeMockTokenHasher(): jest.Mocked<ITokenHasher> {
  return {
    hash: jest.fn().mockReturnValue('hashed-token'),
    generate: jest.fn().mockReturnValue('plain-token'),
  };
}

function makeMockLogger(): jest.Mocked<ILogger> {
  return {
    log: jest.fn(),
    error: jest.fn(),
  };
}

function makeMockUserRepo(): jest.Mocked<IUserRepository<Partial<AuthUser>>> {
  return {
    findById: jest.fn().mockResolvedValue(MOCK_USER),
    findByEmail: jest.fn().mockResolvedValue(null),
    create: jest.fn().mockResolvedValue(MOCK_USER),
    update: jest.fn().mockResolvedValue(MOCK_USER),
  };
}

function makeMockRefreshTokenRepo(): jest.Mocked<
  IRefreshTokenRepository<{
    id: string;
    token: string;
    userId: string;
    expiresAt: Date;
  }>
> {
  return {
    create: jest
      .fn()
      .mockImplementation((data) => Promise.resolve({ id: 'rt-1', ...data })),
    consumeByTokenHash: jest.fn().mockResolvedValue({
      id: 'rt-1',
      token: 'hashed-token',
      userId: 'user-1',
      expiresAt: new Date(Date.now() + 86400_000),
    }),
    deleteAllForUser: jest.fn().mockResolvedValue(undefined),
  };
}

// ── Module builder ────────────────────────────────────────────────────────────

async function buildService(
  overrides: {
    jwtConfig?: JwtConfig;
    jwtSigner?: Partial<IJwtSigner>;
    passwordHasher?: Partial<IPasswordHasher>;
    tokenHasher?: Partial<ITokenHasher>;
    userRepo?: Partial<IUserRepository<Partial<AuthUser>>>;
    refreshTokenRepo?: Partial<IRefreshTokenRepository> | null;
  } = {},
) {
  const jwtConfig = overrides.jwtConfig ?? JWT_CONFIG;
  const jwtSigner = { ...makeMockJwtSigner(), ...overrides.jwtSigner };
  const passwordHasher = {
    ...makeMockPasswordHasher(),
    ...overrides.passwordHasher,
  };
  const tokenHasher = { ...makeMockTokenHasher(), ...overrides.tokenHasher };
  const logger = makeMockLogger();
  const userRepo = { ...makeMockUserRepo(), ...overrides.userRepo };
  const refreshTokenRepo =
    overrides.refreshTokenRepo === null
      ? null
      : { ...makeMockRefreshTokenRepo(), ...overrides.refreshTokenRepo };

  const providers = [
    AuthService,
    { provide: AUTH_CAPABILITIES.JWT, useValue: jwtConfig },
    { provide: PORTS.JWT_SIGNER, useValue: jwtSigner },
    { provide: PORTS.PASSWORD_HASHER, useValue: passwordHasher },
    { provide: PORTS.TOKEN_HASHER, useValue: tokenHasher },
    { provide: PORTS.LOGGER, useValue: logger },
    { provide: PORTS.USER_REPOSITORY, useValue: userRepo },
    ...(refreshTokenRepo !== null
      ? [
          {
            provide: PORTS.REFRESH_TOKEN_REPOSITORY,
            useValue: refreshTokenRepo,
          },
        ]
      : []),
  ];

  const moduleRef = await Test.createTestingModule({ providers }).compile();
  const service = moduleRef.get(AuthService);
  await service.init();

  return {
    service,
    jwtSigner,
    passwordHasher,
    tokenHasher,
    logger,
    userRepo,
    refreshTokenRepo,
  };
}

// helper — asserts the thrown error is an AuthError with the expected code
async function expectAuthError(
  promise: Promise<unknown>,
  code: AuthErrorCode,
): Promise<void> {
  await expect(promise).rejects.toThrow(AuthError);
  await promise.catch((e: AuthError) => {
    expect(e.code).toBe(code);
  });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('AuthService', () => {
  // ── init ──────────────────────────────────────────────────────────────────

  describe('init', () => {
    it('calls jwtSigner.init with the jwt config', async () => {
      const { jwtSigner } = await buildService();
      expect(jwtSigner.init).toHaveBeenCalledWith(JWT_CONFIG);
    });

    it('throws when jwtSigner.init throws (propagates config errors)', async () => {
      await expect(
        buildService({
          jwtSigner: {
            init: jest.fn().mockRejectedValue(new Error('bad key material')),
          },
        }),
      ).rejects.toThrow('bad key material');
    });
  });

  // ── register ──────────────────────────────────────────────────────────────

  describe('register', () => {
    it('hashes the password and creates the user', async () => {
      const { service, userRepo, passwordHasher } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(null) },
      });

      await service.register({ email: 'new@example.com', password: 'secret' });

      expect(passwordHasher.hash).toHaveBeenCalledWith('secret');
      expect(userRepo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'new@example.com',
          password: 'hashed-password',
        }),
      );
    });

    it('returns accessToken and refreshToken', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(null) },
      });

      const result = await service.register({
        email: 'new@example.com',
        password: 'secret',
      });

      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('plain-token');
      expect(result.user.userId).toBe('user-1');
    });

    it('throws AuthError EMAIL_ALREADY_EXISTS when email already exists', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(MOCK_USER) },
      });

      await expectAuthError(
        service.register({ email: 'test@example.com', password: 'secret' }),
        AuthErrorCode.EMAIL_ALREADY_EXISTS,
      );
    });

    it('returns only accessToken when refresh tokens are not configured', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(null) },
        refreshTokenRepo: null,
      });

      const result = await service.register({
        email: 'new@example.com',
        password: 'secret',
      });

      expect(result.accessToken).toBeDefined();
      expect(result.refreshToken).toBeUndefined();
    });

    it('stores expiresAt ~2 weeks out when refreshToken.expiresIn is "2w"', async () => {
      const weekConfig: JwtConfig = {
        ...JWT_CONFIG,
        refreshToken: { expiresIn: '2w' },
      };
      const { service, refreshTokenRepo } = await buildService({
        jwtConfig: weekConfig,
        userRepo: { findByEmail: jest.fn().mockResolvedValue(null) },
      });

      const before = Date.now();
      await service.register({ email: 'w@example.com', password: 'pw' });
      const after = Date.now();

      const [callArgs] = (refreshTokenRepo!.create as jest.Mock).mock.calls;
      const expiresAt: Date = callArgs[0].expiresAt;
      const ttlSeconds = (expiresAt.getTime() - before) / 1000;

      expect(ttlSeconds).toBeGreaterThan(1_209_594);
      expect(expiresAt.getTime()).toBeLessThanOrEqual(
        after + 2 * 604800 * 1000 + 1000,
      );
    });
  });

  // ── loginWithCredentials ──────────────────────────────────────────────────

  describe('loginWithCredentials', () => {
    it('verifies the password against the stored hash', async () => {
      const { service, passwordHasher } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(MOCK_USER) },
      });

      await service.loginWithCredentials({
        email: 'test@example.com',
        password: 'secret',
      });

      expect(passwordHasher.verify).toHaveBeenCalledWith(
        'secret',
        'hashed-password',
      );
    });

    it('throws AuthError INVALID_CREDENTIALS for unknown email', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(null) },
      });

      await expectAuthError(
        service.loginWithCredentials({ email: 'nobody@x.com', password: 'pw' }),
        AuthErrorCode.INVALID_CREDENTIALS,
      );
    });

    it('throws AuthError INVALID_CREDENTIALS for wrong password', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(MOCK_USER) },
        passwordHasher: { verify: jest.fn().mockResolvedValue(false) },
      });

      await expectAuthError(
        service.loginWithCredentials({
          email: 'test@example.com',
          password: 'wrong',
        }),
        AuthErrorCode.INVALID_CREDENTIALS,
      );
    });

    it('throws AuthError INVALID_CREDENTIALS for OAuth-only accounts', async () => {
      const { service } = await buildService({
        userRepo: {
          findByEmail: jest
            .fn()
            .mockResolvedValue({ ...MOCK_USER, password: null }),
        },
      });

      await expectAuthError(
        service.loginWithCredentials({
          email: 'test@example.com',
          password: 'pw',
        }),
        AuthErrorCode.INVALID_CREDENTIALS,
      );
    });
  });

  // ── handleGoogleCallback ──────────────────────────────────────────────────

  describe('handleGoogleCallback', () => {
    it('issues tokens for an existing user', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(MOCK_USER) },
      });

      const result = await service.handleGoogleCallback({ userId: 'user-1' });

      expect(result.accessToken).toBe('mock-access-token');
      expect(result.user.userId).toBe('user-1');
    });

    it('throws AuthError OAUTH_USER_NOT_FOUND if user not found', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(null) },
      });

      await expectAuthError(
        service.handleGoogleCallback({ userId: 'ghost' }),
        AuthErrorCode.OAUTH_USER_NOT_FOUND,
      );
    });
  });

  // ── rotateRefreshToken ────────────────────────────────────────────────────

  describe('rotateRefreshToken', () => {
    it('hashes the incoming token and consumes it atomically', async () => {
      const { service, tokenHasher } = await buildService();

      await service.rotateRefreshToken('plain-token');

      expect(tokenHasher.hash).toHaveBeenCalledWith('plain-token');
    });

    it('calls consumeByTokenHash (atomic find-and-delete)', async () => {
      const { service, refreshTokenRepo } = await buildService();

      await service.rotateRefreshToken('plain-token');

      expect(refreshTokenRepo?.consumeByTokenHash).toHaveBeenCalledWith(
        'hashed-token',
      );
    });

    it('returns a fresh token pair', async () => {
      const { service } = await buildService();

      const result = await service.rotateRefreshToken('plain-token');

      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('plain-token');
    });

    it('throws AuthError REFRESH_TOKEN_INVALID when consumeByTokenHash returns null', async () => {
      const { service } = await buildService({
        refreshTokenRepo: {
          consumeByTokenHash: jest.fn().mockResolvedValue(null),
        },
      });

      await expectAuthError(
        service.rotateRefreshToken('bad-token'),
        AuthErrorCode.REFRESH_TOKEN_INVALID,
      );
    });

    it('throws AuthError REFRESH_TOKEN_EXPIRED for an expired token', async () => {
      const { service } = await buildService({
        refreshTokenRepo: {
          consumeByTokenHash: jest.fn().mockResolvedValue({
            id: 'rt-expired',
            token: 'hashed-token',
            userId: 'user-1',
            expiresAt: new Date(Date.now() - 1000),
          }),
        },
      });

      await expectAuthError(
        service.rotateRefreshToken('plain-token'),
        AuthErrorCode.REFRESH_TOKEN_EXPIRED,
      );
    });

    it('throws AuthError REFRESH_NOT_ENABLED when refresh tokens are not configured', async () => {
      const { service } = await buildService({ refreshTokenRepo: null });

      await expectAuthError(
        service.rotateRefreshToken('token'),
        AuthErrorCode.REFRESH_NOT_ENABLED,
      );
    });

    it('throws AuthError REFRESH_TOKEN_INVALID for empty token string', async () => {
      const { service } = await buildService();

      await expectAuthError(
        service.rotateRefreshToken(''),
        AuthErrorCode.REFRESH_TOKEN_INVALID,
      );
    });
  });

  // ── logout ────────────────────────────────────────────────────────────────

  describe('logout', () => {
    it('revokes all refresh tokens for the user', async () => {
      const { service, refreshTokenRepo } = await buildService();

      await service.logout('user-1');

      expect(refreshTokenRepo?.deleteAllForUser).toHaveBeenCalledWith('user-1');
    });

    it('does not throw when refresh tokens are not configured', async () => {
      const { service } = await buildService({ refreshTokenRepo: null });

      await expect(service.logout('user-1')).resolves.toBeUndefined();
    });
  });

  // ── verifyAccessToken ─────────────────────────────────────────────────────

  describe('verifyAccessToken', () => {
    it('returns RequestUser for a valid access token', async () => {
      const { service } = await buildService();

      const result = await service.verifyAccessToken('valid-token');

      expect(result).toEqual({ userId: 'user-1' });
    });

    it('throws AuthError ACCESS_TOKEN_INVALID when jwtSigner.verify throws InvalidTokenError', async () => {
      const { service } = await buildService({
        jwtSigner: {
          verify: jest
            .fn()
            .mockRejectedValue(new InvalidTokenError('token expired')),
        },
      });

      await expectAuthError(
        service.verifyAccessToken('bad'),
        AuthErrorCode.ACCESS_TOKEN_INVALID,
      );
    });

    it('re-throws non-InvalidTokenError errors as infrastructure failures (not wrapped in AuthError)', async () => {
      const boom = new Error('KMS connection timeout');
      const { service } = await buildService({
        jwtSigner: { verify: jest.fn().mockRejectedValue(boom) },
      });

      // Must propagate as-is — not wrapped in AuthError — so it surfaces as 500.
      await expect(service.verifyAccessToken('token')).rejects.toThrow(boom);
      await expect(service.verifyAccessToken('token')).rejects.not.toThrow(
        AuthError,
      );
    });

    it('throws AuthError ACCESS_TOKEN_INVALID when payload type is not "access"', async () => {
      const { service } = await buildService({
        jwtSigner: {
          verify: jest.fn().mockResolvedValue({ sub: 'u', type: 'refresh' }),
        },
      });

      await expectAuthError(
        service.verifyAccessToken('refresh-token'),
        AuthErrorCode.ACCESS_TOKEN_INVALID,
      );
    });

    it('throws AuthError ACCESS_TOKEN_INVALID when sub is missing', async () => {
      const { service } = await buildService({
        jwtSigner: {
          verify: jest.fn().mockResolvedValue({ sub: '', type: 'access' }),
        },
      });

      await expectAuthError(
        service.verifyAccessToken('token'),
        AuthErrorCode.ACCESS_TOKEN_INVALID,
      );
    });
  });

  // ── changePassword ────────────────────────────────────────────────────────

  describe('changePassword', () => {
    it('hashes the new password and updates the user', async () => {
      const { service, userRepo, passwordHasher } = await buildService({
        passwordHasher: {
          verify: jest
            .fn()
            .mockResolvedValueOnce(true) // current password valid
            .mockResolvedValueOnce(false), // new ≠ current
        },
      });

      await service.changePassword({
        userId: 'user-1',
        currentPassword: 'old',
        newPassword: 'new',
      });

      expect(passwordHasher.hash).toHaveBeenCalledWith('new');
      expect(userRepo.update).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({ password: 'hashed-password' }),
      );
    });

    it('throws AuthError USER_NOT_FOUND when user does not exist', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(null) },
      });

      await expectAuthError(
        service.changePassword({
          userId: 'ghost',
          currentPassword: 'old',
          newPassword: 'new',
        }),
        AuthErrorCode.USER_NOT_FOUND,
      );
    });

    it('throws AuthError INVALID_CREDENTIALS when current password is wrong', async () => {
      const { service } = await buildService({
        passwordHasher: { verify: jest.fn().mockResolvedValue(false) },
      });

      await expectAuthError(
        service.changePassword({
          userId: 'user-1',
          currentPassword: 'wrong',
          newPassword: 'new',
        }),
        AuthErrorCode.INVALID_CREDENTIALS,
      );
    });

    it('throws AuthError PASSWORD_SAME_AS_OLD when new password equals current', async () => {
      const { service } = await buildService({
        passwordHasher: { verify: jest.fn().mockResolvedValue(true) },
      });

      await expectAuthError(
        service.changePassword({
          userId: 'user-1',
          currentPassword: 'same',
          newPassword: 'same',
        }),
        AuthErrorCode.PASSWORD_SAME_AS_OLD,
      );
    });

    it('throws AuthError OAUTH_ACCOUNT_NO_PASSWORD for OAuth-only accounts', async () => {
      const { service } = await buildService({
        userRepo: {
          findById: jest
            .fn()
            .mockResolvedValue({ ...MOCK_USER, password: null }),
        },
      });

      await expectAuthError(
        service.changePassword({
          userId: 'user-1',
          currentPassword: 'old',
          newPassword: 'new',
        }),
        AuthErrorCode.OAUTH_ACCOUNT_NO_PASSWORD,
      );
    });
  });

  // ── setPassword ───────────────────────────────────────────────────────────

  describe('setPassword', () => {
    it('hashes and saves the new password', async () => {
      const { service, userRepo } = await buildService();

      await service.setPassword({ userId: 'user-1', newPassword: 'new' });

      expect(userRepo.update).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({ password: 'hashed-password' }),
      );
    });

    it('throws AuthError USER_NOT_FOUND when user does not exist', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(null) },
      });

      await expectAuthError(
        service.setPassword({ userId: 'ghost', newPassword: 'new' }),
        AuthErrorCode.USER_NOT_FOUND,
      );
    });
  });
});
