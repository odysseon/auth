import { UnauthorizedException } from '@nestjs/common';
import { GoogleStrategy } from './google.strategy';
import type { IGoogleUserRepository } from '../interfaces';
import type { AuthUser } from '../interfaces/user-model/user.interface';
import type { Profile, VerifyCallback } from 'passport-google-oauth20';

// Mock passport-google-oauth20's Strategy so the constructor's super() call
// does not attempt real OAuth registration. This lets us test the constructor
// guard (null config) AND the happy path (valid config → super() called)
// without a live Passport/Express setup.
jest.mock('passport-google-oauth20', () => {
  const MockStrategy = jest.fn().mockImplementation(function (
    this: object,
    _opts: unknown,
  ) {});
  return { Strategy: MockStrategy };
});

/**
 * GoogleStrategy.validate() contains all the find-or-create logic.
 * We test it directly without a Passport pipeline — the constructor
 * wiring to passport-google-oauth20 is an adapter detail, not logic.
 */
describe('GoogleStrategy', () => {
  const EXISTING_USER = {
    id: 'user-1',
    email: 'user@example.com',
    googleId: 'google-123',
    password: null,
  };

  function buildProfile(overrides: Partial<Profile> = {}): Profile {
    return {
      id: 'google-123',
      displayName: 'Test User',
      profileUrl: '',
      provider: 'google',
      emails: [{ value: 'user@example.com', verified: true }],
      photos: [],
      _raw: '',
      _json: { iss: '', aud: '', sub: '', iat: 0, exp: 0 },
      ...overrides,
    };
  }

  function buildStrategy(
    repoOverrides: Partial<IGoogleUserRepository<Partial<AuthUser>>> = {},
  ) {
    const defaultRepo: IGoogleUserRepository<Partial<AuthUser>> = {
      findById: jest.fn().mockResolvedValue(EXISTING_USER),
      findByEmail: jest.fn().mockResolvedValue(null),
      findByGoogleId: jest.fn().mockResolvedValue(EXISTING_USER),
      create: jest.fn().mockResolvedValue(EXISTING_USER),
      update: jest.fn().mockResolvedValue(EXISTING_USER),
    };

    const repo = { ...defaultRepo, ...repoOverrides };

    // Bypass PassportStrategy constructor — we only test validate().
    const strategy = Object.create(GoogleStrategy.prototype) as GoogleStrategy;
    (strategy as unknown as { userRepo: typeof repo }).userRepo = repo;
    return { strategy, repo };
  }

  describe('validate', () => {
    it('resolves with userId when user already has googleId linked', async () => {
      const { strategy } = buildStrategy({
        findByGoogleId: jest.fn().mockResolvedValue(EXISTING_USER),
      });
      const done = jest.fn() as jest.MockedFunction<VerifyCallback>;

      await strategy.validate('at', 'rt', buildProfile(), done);

      expect(done).toHaveBeenCalledWith(null, { userId: 'user-1' });
    });

    it('links googleId to an existing email account (find-by-email path)', async () => {
      const emailUser = {
        id: 'user-2',
        email: 'user@example.com',
        googleId: null,
      };
      const { strategy, repo } = buildStrategy({
        findByGoogleId: jest.fn().mockResolvedValue(null),
        findByEmail: jest.fn().mockResolvedValue(emailUser),
        update: jest
          .fn()
          .mockResolvedValue({ ...emailUser, googleId: 'google-456' }),
      });
      const done = jest.fn() as jest.MockedFunction<VerifyCallback>;

      await strategy.validate(
        'at',
        'rt',
        buildProfile({ id: 'google-456' }),
        done,
      );

      expect(repo.update).toHaveBeenCalledWith(
        'user-2',
        expect.objectContaining({ googleId: 'google-456' }),
      );
      expect(done).toHaveBeenCalledWith(null, { userId: 'user-2' });
    });

    it('creates a new user when no existing account matches', async () => {
      const newUser = {
        id: 'user-3',
        email: 'new@example.com',
        googleId: 'google-789',
      };
      const { strategy, repo } = buildStrategy({
        findByGoogleId: jest.fn().mockResolvedValue(null),
        findByEmail: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue(newUser),
      });
      const done = jest.fn() as jest.MockedFunction<VerifyCallback>;

      await strategy.validate(
        'at',
        'rt',
        buildProfile({
          id: 'google-789',
          emails: [{ value: 'new@example.com', verified: true }],
        }),
        done,
      );

      expect(repo.create).toHaveBeenCalledWith(
        expect.objectContaining({
          email: 'new@example.com',
          googleId: 'google-789',
        }),
      );
      expect(done).toHaveBeenCalledWith(null, { userId: 'user-3' });
    });

    it('calls done with UnauthorizedException when no email in profile', async () => {
      const { strategy } = buildStrategy();
      const done = jest.fn() as jest.MockedFunction<VerifyCallback>;

      await strategy.validate('at', 'rt', buildProfile({ emails: [] }), done);

      expect(done).toHaveBeenCalledWith(expect.any(UnauthorizedException));
    });

    it('calls done with UnauthorizedException when user id cannot be resolved', async () => {
      const { strategy } = buildStrategy({
        findByGoogleId: jest.fn().mockResolvedValue(null),
        findByEmail: jest.fn().mockResolvedValue(null),
        create: jest.fn().mockResolvedValue({ id: undefined }),
      });
      const done = jest.fn() as jest.MockedFunction<VerifyCallback>;

      await strategy.validate('at', 'rt', buildProfile(), done);

      expect(done).toHaveBeenCalledWith(expect.any(UnauthorizedException));
    });

    it('calls done with the error when an unexpected exception is thrown', async () => {
      const boom = new Error('DB connection lost');
      const { strategy } = buildStrategy({
        findByGoogleId: jest.fn().mockRejectedValue(boom),
      });
      const done = jest.fn() as jest.MockedFunction<VerifyCallback>;

      await strategy.validate('at', 'rt', buildProfile(), done);

      expect(done).toHaveBeenCalledWith(boom);
    });
  });

  describe('constructor', () => {
    it('throws when no Google config is provided', () => {
      // Simulates the module being misconfigured: 'google' listed in
      // enabledCapabilities but no google config supplied.
      expect(() => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        new GoogleStrategy(null as any, {} as any);
      }).toThrow('GoogleStrategy instantiated but no Google config');
    });

    it('constructs without throwing when valid config is provided', () => {
      // Exercises the userRepo parameter line (49) and the super() call (57)
      // that are only reached when config is truthy.
      const config = {
        clientID: 'id',
        clientSecret: 'secret',
        callbackURL: 'https://example.com/callback',
      };
      const repo = {} as IGoogleUserRepository<Partial<AuthUser>>;
      expect(() => new GoogleStrategy(config, repo)).not.toThrow();
    });

    it('uses default scope when scope is not configured', () => {
      const config = {
        clientID: 'id',
        clientSecret: 'secret',
        callbackURL: 'https://example.com/callback',
      };
      const repo = {} as IGoogleUserRepository<Partial<AuthUser>>;
      // Should not throw — the scope ?? ['email', 'profile'] fallback fires.
      expect(() => new GoogleStrategy(config, repo)).not.toThrow();
    });
  });
});
