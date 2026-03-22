import { Argon2PasswordHasher } from './argon2-password-hasher.adapter';

describe('Argon2PasswordHasher', () => {
  let hasher: Argon2PasswordHasher;

  beforeEach(() => {
    hasher = new Argon2PasswordHasher();
  });

  describe('hash', () => {
    it('returns a string that starts with the argon2 prefix', async () => {
      const hash = await hasher.hash('my-password');
      // argon2id hashes always start with $argon2id$
      expect(hash).toMatch(/^\$argon2id\$/);
    });

    it('produces a different hash on each call (unique salts)', async () => {
      const hash1 = await hasher.hash('same-password');
      const hash2 = await hasher.hash('same-password');
      expect(hash1).not.toBe(hash2);
    });
  });

  describe('verify', () => {
    it('returns true for the correct password', async () => {
      const hash = await hasher.hash('correct-password');
      expect(await hasher.verify('correct-password', hash)).toBe(true);
    });

    it('returns false for the wrong password', async () => {
      const hash = await hasher.hash('correct-password');
      expect(await hasher.verify('wrong-password', hash)).toBe(false);
    });

    it('returns false for a malformed hash instead of throwing', async () => {
      expect(await hasher.verify('password', 'not-a-valid-hash')).toBe(false);
    });

    it('returns false for an empty hash', async () => {
      expect(await hasher.verify('password', '')).toBe(false);
    });
  });

  describe('missing argon2 package', () => {
    it('throws a descriptive error when argon2 is not installed', async () => {
      // jest.isolateModules creates a fresh module registry scoped to this
      // callback. jest.mock inside it is registered before any require() runs,
      // so the dynamic import('argon2') compiled to require() sees the mock.
      await jest.isolateModules(async () => {
        jest.mock('argon2', () => {
          throw new Error('Cannot find module');
        });

        const { Argon2PasswordHasher: FreshHasher } =
          await import('./argon2-password-hasher.adapter');

        const freshHasher = new FreshHasher();

        await expect(freshHasher.hash('password')).rejects.toThrow(
          'Argon2PasswordHasher requires the `argon2` package',
        );
      });
    });
  });
});
