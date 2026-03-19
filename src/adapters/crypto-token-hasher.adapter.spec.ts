import { CryptoTokenHasher } from './crypto-token-hasher.adapter';

describe('CryptoTokenHasher', () => {
  let hasher: CryptoTokenHasher;

  beforeEach(() => {
    hasher = new CryptoTokenHasher();
  });

  describe('hash', () => {
    it('returns a 64-character hex string (SHA-256)', () => {
      const result = hasher.hash('some-token');
      expect(result).toMatch(/^[0-9a-f]{64}$/);
    });

    it('is deterministic — same input yields same output', () => {
      expect(hasher.hash('abc')).toBe(hasher.hash('abc'));
    });

    it('is collision-resistant — different inputs yield different hashes', () => {
      expect(hasher.hash('token-a')).not.toBe(hasher.hash('token-b'));
    });

    it('produces the known SHA-256 hash for empty string', () => {
      // SHA-256('') = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
      expect(hasher.hash('')).toBe(
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
      );
    });
  });

  describe('generate', () => {
    it('returns a hex string of length bytes * 2', () => {
      expect(hasher.generate(32)).toHaveLength(64);
      expect(hasher.generate(16)).toHaveLength(32);
      expect(hasher.generate(64)).toHaveLength(128);
    });

    it('defaults to 32 bytes (64 hex chars)', () => {
      expect(hasher.generate()).toHaveLength(64);
    });

    it('generates unique tokens on each call', () => {
      const tokens = new Set(
        Array.from({ length: 100 }, () => hasher.generate()),
      );
      expect(tokens.size).toBe(100);
    });

    it('only contains hex characters', () => {
      expect(hasher.generate(32)).toMatch(/^[0-9a-f]+$/);
    });
  });
});
