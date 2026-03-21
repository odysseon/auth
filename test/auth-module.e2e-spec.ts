/**
 * E2E smoke test for AuthModule.
 *
 * Boots a minimal NestJS application wired with in-memory stub repositories
 * and verifies the full authentication lifecycle:
 *   register → login → refresh → logout
 *
 * No real database. No real argon2 (replaced with a fast plaintext stub).
 * No real HTTP server — requests go through the NestJS test client.
 */
import { Test, TestingModule } from '@nestjs/testing';
import { INestApplication, Injectable } from '@nestjs/common';
import { AuthModule } from '../src/core/auth.module';
import { AuthError, AuthErrorCode } from '../src/errors/auth-error';
import type { IUserRepository } from '../src/interfaces/user-model/user-repository.interface';
import type { IRefreshTokenRepository } from '../src/interfaces/refresh-token/refresh-token.interface';
import type { IRefreshToken } from '../src/interfaces/refresh-token/refresh-token.interface';
import type { AuthUser } from '../src/interfaces/user-model/user.interface';
import type { IPasswordHasher } from '../src/interfaces/ports/password-hasher.port';
import { AuthService } from '../src/core/auth.service';

// ── In-memory stubs ─────────────────────────────────────────────────────────

type TestUser = Required<Omit<AuthUser, 'isEmailVerified'>> & { id: string };

@Injectable()
class InMemoryUserRepository implements IUserRepository<TestUser> {
  private store = new Map<string, TestUser>();
  private idSeq = 0;

  findById(id: string) {
    return Promise.resolve(this.store.get(id) ?? null);
  }
  findByEmail(email: string) {
    return Promise.resolve(
      [...this.store.values()].find((u) => u.email === email) ?? null,
    );
  }
  create(data: Partial<TestUser>) {
    const id = String(++this.idSeq);
    const user: TestUser = {
      id,
      email: data.email ?? '',
      password: data.password ?? null,
      googleId: data.googleId ?? null,
    };
    this.store.set(id, user);
    return Promise.resolve(user);
  }
  update(id: string, data: Partial<TestUser>) {
    const existing = this.store.get(id);
    if (!existing) throw new Error(`User ${id} not found`);
    const updated = { ...existing, ...data };
    this.store.set(id, updated);
    return Promise.resolve(updated);
  }
}

@Injectable()
class InMemoryRefreshTokenRepository implements IRefreshTokenRepository {
  private store = new Map<string, IRefreshToken>();
  private idSeq = 0;

  create(data: Omit<IRefreshToken, 'id'>) {
    const id = String(++this.idSeq);
    const record: IRefreshToken = { id, ...data };
    this.store.set(id, record);
    return Promise.resolve(record);
  }
  consumeByTokenHash(hash: string) {
    const record = [...this.store.values()].find((t) => t.token === hash);
    if (!record) return Promise.resolve(null);
    this.store.delete(record.id);
    return Promise.resolve(record);
  }
  deleteAllForUser(userId: string) {
    for (const [id, token] of this.store) {
      if (token.userId === userId) this.store.delete(id);
    }
    return Promise.resolve();
  }
}

/** Fast stub — stores plaintext, no real hashing in tests. */
@Injectable()
class PlaintextPasswordHasher implements IPasswordHasher {
  async hash(password: string) {
    return `plain:${password}`;
  }
  async verify(password: string, hash: string) {
    return hash === `plain:${password}`;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

async function expectAuthError(promise: Promise<unknown>, code: AuthErrorCode) {
  await expect(promise).rejects.toBeInstanceOf(AuthError);
  await expect(promise).rejects.toHaveProperty('code', code);
}

// ── Test suite ───────────────────────────────────────────────────────────────

describe('AuthModule (e2e)', () => {
  let app: INestApplication;
  let authService: AuthService;

  beforeAll(async () => {
    const moduleRef: TestingModule = await Test.createTestingModule({
      imports: [
        AuthModule.forRootAsync({
          useFactory: () => ({
            jwt: {
              type: 'symmetric',
              secret: 'e2e-test-secret-must-be-long-enough',
              accessToken: { expiresIn: '15m', algorithm: 'HS256' },
              refreshToken: { expiresIn: '7d' },
            },
          }),
          userRepository: InMemoryUserRepository,
          refreshTokenRepository: InMemoryRefreshTokenRepository,
          enabledCapabilities: ['credentials'],
          passwordHasher: PlaintextPasswordHasher,
        }),
      ],
    }).compile();

    app = moduleRef.createNestApplication();
    await app.init();

    authService = moduleRef.get(AuthService);
  });

  afterAll(async () => {
    await app.close();
  });

  describe('register', () => {
    it('creates a new user and returns a token pair', async () => {
      const result = await authService.register({
        email: 'test@example.com',
        password: 'password123',
      });

      expect(result.user.userId).toBeDefined();
      expect(typeof result.accessToken).toBe('string');
      expect(typeof result.refreshToken).toBe('string');
    });

    it('throws AuthError EMAIL_ALREADY_EXISTS for duplicate email', async () => {
      await authService.register({
        email: 'duplicate@example.com',
        password: 'password123',
      });

      await expectAuthError(
        authService.register({
          email: 'duplicate@example.com',
          password: 'password456',
        }),
        AuthErrorCode.EMAIL_ALREADY_EXISTS,
      );
    });
  });

  describe('loginWithCredentials', () => {
    beforeAll(async () => {
      await authService.register({
        email: 'login@example.com',
        password: 'correct-password',
      });
    });

    it('returns a token pair on valid credentials', async () => {
      const result = await authService.loginWithCredentials({
        email: 'login@example.com',
        password: 'correct-password',
      });

      expect(result.user.userId).toBeDefined();
      expect(typeof result.accessToken).toBe('string');
    });

    it('throws AuthError INVALID_CREDENTIALS on wrong password', async () => {
      await expectAuthError(
        authService.loginWithCredentials({
          email: 'login@example.com',
          password: 'wrong-password',
        }),
        AuthErrorCode.INVALID_CREDENTIALS,
      );
    });

    it('throws AuthError INVALID_CREDENTIALS for unknown email', async () => {
      await expectAuthError(
        authService.loginWithCredentials({
          email: 'nobody@example.com',
          password: 'password',
        }),
        AuthErrorCode.INVALID_CREDENTIALS,
      );
    });
  });

  describe('rotateRefreshToken', () => {
    it('issues a fresh token pair and invalidates the old refresh token', async () => {
      const first = await authService.register({
        email: 'rotate@example.com',
        password: 'password',
      });
      const second = await authService.rotateRefreshToken(first.refreshToken!);

      expect(second.accessToken).toBeDefined();
      expect(second.refreshToken).toBeDefined();

      await expectAuthError(
        authService.rotateRefreshToken(first.refreshToken!),
        AuthErrorCode.REFRESH_TOKEN_INVALID,
      );
    });
  });

  describe('logout', () => {
    it('revokes all refresh tokens so they cannot be rotated', async () => {
      const { user, refreshToken } = await authService.register({
        email: 'logout@example.com',
        password: 'password',
      });

      await authService.logout(user.userId);

      await expectAuthError(
        authService.rotateRefreshToken(refreshToken!),
        AuthErrorCode.REFRESH_TOKEN_INVALID,
      );
    });
  });

  describe('changePassword', () => {
    it('allows login with new password after change', async () => {
      const { user } = await authService.register({
        email: 'changepw@example.com',
        password: 'old-password',
      });

      await authService.changePassword({
        userId: user.userId,
        currentPassword: 'old-password',
        newPassword: 'new-password',
      });

      const result = await authService.loginWithCredentials({
        email: 'changepw@example.com',
        password: 'new-password',
      });
      expect(result.user.userId).toBe(user.userId);
    });

    it('throws AuthError INVALID_CREDENTIALS when current password is wrong', async () => {
      const { user } = await authService.register({
        email: 'changepw-fail@example.com',
        password: 'password',
      });

      await expectAuthError(
        authService.changePassword({
          userId: user.userId,
          currentPassword: 'wrong',
          newPassword: 'new-password',
        }),
        AuthErrorCode.INVALID_CREDENTIALS,
      );
    });
  });
});
