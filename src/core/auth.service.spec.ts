import { Test } from '@nestjs/testing';
import {
  UnauthorizedException,
  ConflictException,
  BadRequestException,
  NotFoundException,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AUTH_CAPABILITIES, PORTS } from '../constants';
import type { IJwtSigner } from '../interfaces/ports/jwt-signer.port';
import type { IPasswordHasher } from '../interfaces/ports/password-hasher.port';
import type { ITokenHasher } from '../interfaces/ports/token-hasher.port';
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
  isEmailVerified: false,
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
    findByTokenHash: jest.fn().mockResolvedValue({
      id: 'rt-1',
      token: 'hashed-token',
      userId: 'user-1',
      expiresAt: new Date(Date.now() + 86400_000),
    }),
    deleteById: jest.fn().mockResolvedValue(undefined),
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
  await service.onModuleInit();

  return {
    service,
    jwtSigner,
    passwordHasher,
    tokenHasher,
    userRepo,
    refreshTokenRepo,
  };
}

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('AuthService', () => {
  // ── onModuleInit ──────────────────────────────────────────────────────────

  describe('onModuleInit', () => {
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

    it('throws ConflictException when email already exists', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(MOCK_USER) },
      });

      await expect(
        service.register({ email: 'test@example.com', password: 'secret' }),
      ).rejects.toThrow(ConflictException);
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

      // 2 weeks = 1_209_600 seconds. Allow a few seconds of test latency.
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

    it('throws UnauthorizedException for unknown email', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(null) },
      });

      await expect(
        service.loginWithCredentials({ email: 'nobody@x.com', password: 'pw' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('throws UnauthorizedException for wrong password', async () => {
      const { service } = await buildService({
        userRepo: { findByEmail: jest.fn().mockResolvedValue(MOCK_USER) },
        passwordHasher: { verify: jest.fn().mockResolvedValue(false) },
      });

      await expect(
        service.loginWithCredentials({
          email: 'test@example.com',
          password: 'wrong',
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('throws UnauthorizedException for OAuth-only accounts', async () => {
      const { service } = await buildService({
        userRepo: {
          findByEmail: jest
            .fn()
            .mockResolvedValue({ ...MOCK_USER, password: null }),
        },
      });

      await expect(
        service.loginWithCredentials({
          email: 'test@example.com',
          password: 'pw',
        }),
      ).rejects.toThrow(UnauthorizedException);
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

    it('throws UnauthorizedException if user not found', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(null) },
      });

      await expect(
        service.handleGoogleCallback({ userId: 'ghost' }),
      ).rejects.toThrow(UnauthorizedException);
    });
  });

  // ── rotateRefreshToken ────────────────────────────────────────────────────

  describe('rotateRefreshToken', () => {
    it('hashes the incoming token and looks it up', async () => {
      const { service, tokenHasher } = await buildService();

      await service.rotateRefreshToken('plain-token');

      expect(tokenHasher.hash).toHaveBeenCalledWith('plain-token');
    });

    it('deletes the old record before issuing new tokens (one-time use)', async () => {
      const { service, refreshTokenRepo } = await buildService();

      await service.rotateRefreshToken('plain-token');

      expect(refreshTokenRepo?.deleteById).toHaveBeenCalledWith('rt-1');
    });

    it('returns a fresh token pair', async () => {
      const { service } = await buildService();

      const result = await service.rotateRefreshToken('plain-token');

      expect(result.accessToken).toBe('mock-access-token');
      expect(result.refreshToken).toBe('plain-token');
    });

    it('throws UnauthorizedException for an unknown token', async () => {
      const { service } = await buildService({
        refreshTokenRepo: {
          findByTokenHash: jest.fn().mockResolvedValue(null),
        },
      });

      await expect(service.rotateRefreshToken('bad-token')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('throws UnauthorizedException for an expired token and deletes it', async () => {
      const { service, refreshTokenRepo } = await buildService({
        refreshTokenRepo: {
          findByTokenHash: jest.fn().mockResolvedValue({
            id: 'rt-expired',
            token: 'hashed-token',
            userId: 'user-1',
            expiresAt: new Date(Date.now() - 1000),
          }),
        },
      });

      await expect(service.rotateRefreshToken('plain-token')).rejects.toThrow(
        'expired',
      );
      expect(refreshTokenRepo?.deleteById).toHaveBeenCalledWith('rt-expired');
    });

    it('throws BadRequestException when refresh tokens are not configured', async () => {
      const { service } = await buildService({ refreshTokenRepo: null });

      await expect(service.rotateRefreshToken('token')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('throws BadRequestException for empty token string', async () => {
      const { service } = await buildService();

      await expect(service.rotateRefreshToken('')).rejects.toThrow(
        BadRequestException,
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

    it('throws UnauthorizedException when jwtSigner.verify throws', async () => {
      const { service } = await buildService({
        jwtSigner: {
          verify: jest.fn().mockRejectedValue(new Error('expired')),
        },
      });

      await expect(service.verifyAccessToken('bad')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('throws UnauthorizedException when payload type is not "access"', async () => {
      const { service } = await buildService({
        jwtSigner: {
          verify: jest.fn().mockResolvedValue({ sub: 'u', type: 'refresh' }),
        },
      });

      await expect(service.verifyAccessToken('refresh-token')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('throws UnauthorizedException when sub is missing', async () => {
      const { service } = await buildService({
        jwtSigner: {
          verify: jest.fn().mockResolvedValue({ sub: '', type: 'access' }),
        },
      });

      await expect(service.verifyAccessToken('token')).rejects.toThrow(
        UnauthorizedException,
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

    it('throws NotFoundException when user does not exist', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(null) },
      });

      await expect(
        service.changePassword({
          userId: 'ghost',
          currentPassword: 'old',
          newPassword: 'new',
        }),
      ).rejects.toThrow(NotFoundException);
    });

    it('throws UnauthorizedException when current password is wrong', async () => {
      const { service } = await buildService({
        passwordHasher: { verify: jest.fn().mockResolvedValue(false) },
      });

      await expect(
        service.changePassword({
          userId: 'user-1',
          currentPassword: 'wrong',
          newPassword: 'new',
        }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('throws BadRequestException when new password equals current', async () => {
      const { service } = await buildService({
        passwordHasher: { verify: jest.fn().mockResolvedValue(true) },
      });

      await expect(
        service.changePassword({
          userId: 'user-1',
          currentPassword: 'same',
          newPassword: 'same',
        }),
      ).rejects.toThrow(BadRequestException);
    });

    it('throws BadRequestException for OAuth-only accounts', async () => {
      const { service } = await buildService({
        userRepo: {
          findById: jest
            .fn()
            .mockResolvedValue({ ...MOCK_USER, password: null }),
        },
      });

      await expect(
        service.changePassword({
          userId: 'user-1',
          currentPassword: 'old',
          newPassword: 'new',
        }),
      ).rejects.toThrow(BadRequestException);
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

    it('throws NotFoundException when user does not exist', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(null) },
      });

      await expect(
        service.setPassword({ userId: 'ghost', newPassword: 'new' }),
      ).rejects.toThrow(NotFoundException);
    });
  });

  // ── verifyEmail ───────────────────────────────────────────────────────────

  describe('verifyEmail', () => {
    it('marks the email as verified', async () => {
      const { service, userRepo } = await buildService({
        userRepo: {
          findById: jest
            .fn()
            .mockResolvedValue({ ...MOCK_USER, isEmailVerified: false }),
        },
      });

      const result = await service.verifyEmail('user-1');

      expect(result.message).toBe('Email verified successfully');
      expect(userRepo.update).toHaveBeenCalledWith(
        'user-1',
        expect.objectContaining({ isEmailVerified: true }),
      );
    });

    it('is idempotent when already verified', async () => {
      const { service } = await buildService({
        userRepo: {
          findById: jest
            .fn()
            .mockResolvedValue({ ...MOCK_USER, isEmailVerified: true }),
        },
      });

      const result = await service.verifyEmail('user-1');
      expect(result.message).toBe('Email already verified');
    });

    it('throws NotFoundException when user does not exist', async () => {
      const { service } = await buildService({
        userRepo: { findById: jest.fn().mockResolvedValue(null) },
      });

      await expect(service.verifyEmail('ghost')).rejects.toThrow(
        NotFoundException,
      );
    });
  });
});
