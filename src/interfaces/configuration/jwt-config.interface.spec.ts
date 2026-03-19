import {
  isSymmetric,
  isAsymmetric,
  validateJwtConfig,
} from './jwt-config.interface';
import type { JwtConfig } from './jwt-config.interface';

const VALID_SYMMETRIC: JwtConfig = {
  type: 'symmetric',
  secret: 'my-secret',
  accessToken: { expiresIn: '15m' },
};

const VALID_ASYMMETRIC: JwtConfig = {
  type: 'asymmetric',
  privateKey: '-----BEGIN PRIVATE KEY-----',
  publicKey: '-----BEGIN PUBLIC KEY-----',
  accessToken: { expiresIn: '15m' },
};

describe('isSymmetric', () => {
  it('returns true for symmetric config', () => {
    expect(isSymmetric(VALID_SYMMETRIC)).toBe(true);
  });

  it('returns false for asymmetric config', () => {
    expect(isSymmetric(VALID_ASYMMETRIC)).toBe(false);
  });
});

describe('isAsymmetric', () => {
  it('returns true for asymmetric config', () => {
    expect(isAsymmetric(VALID_ASYMMETRIC)).toBe(true);
  });

  it('returns false for symmetric config', () => {
    expect(isAsymmetric(VALID_SYMMETRIC)).toBe(false);
  });
});

describe('validateJwtConfig', () => {
  describe('valid configs', () => {
    it('does not throw for a valid symmetric config', () => {
      expect(() => validateJwtConfig(VALID_SYMMETRIC)).not.toThrow();
    });

    it('does not throw for a valid asymmetric config', () => {
      expect(() => validateJwtConfig(VALID_ASYMMETRIC)).not.toThrow();
    });

    it('does not throw when expiresIn is a number (seconds)', () => {
      expect(() =>
        validateJwtConfig({
          ...VALID_SYMMETRIC,
          accessToken: { expiresIn: 900 },
        }),
      ).not.toThrow();
    });
  });

  describe('missing expiresIn', () => {
    it('throws when accessToken.expiresIn is missing', () => {
      const bad = {
        ...VALID_SYMMETRIC,
        accessToken: { expiresIn: '' },
      } as unknown as JwtConfig;
      expect(() => validateJwtConfig(bad)).toThrow('expiresIn is required');
    });
  });

  describe('symmetric-specific validation', () => {
    it('throws when secret is empty string', () => {
      const bad: JwtConfig = {
        type: 'symmetric',
        secret: '',
        accessToken: { expiresIn: '15m' },
      };
      expect(() => validateJwtConfig(bad)).toThrow('secret is required');
    });
  });

  describe('asymmetric-specific validation', () => {
    it('throws when privateKey is missing', () => {
      const bad: JwtConfig = {
        type: 'asymmetric',
        privateKey: '',
        publicKey: '-----BEGIN PUBLIC KEY-----',
        accessToken: { expiresIn: '15m' },
      };
      expect(() => validateJwtConfig(bad)).toThrow(
        'jwt.privateKey and jwt.publicKey are both required',
      );
    });

    it('throws when publicKey is missing', () => {
      const bad: JwtConfig = {
        type: 'asymmetric',
        privateKey: '-----BEGIN PRIVATE KEY-----',
        publicKey: '',
        accessToken: { expiresIn: '15m' },
      };
      expect(() => validateJwtConfig(bad)).toThrow(
        'jwt.privateKey and jwt.publicKey are both required',
      );
    });
  });
});
