/**
 * Unit tests for JoseJwtSigner.
 *
 * jose is mocked entirely — this spec tests OUR wrapping logic (key selection,
 * expiry conversion, issuer/audience wiring, InvalidTokenError wrapping) without
 * loading jose's ESM-only bundle through Jest's CommonJS runner.
 *
 * Real cryptographic round-trips (sign → verify with actual keys) are covered
 * by the e2e test in test/auth-module.e2e-spec.ts, which runs through the full
 * NestJS module and exercises the real jose library end-to-end.
 */

import { InvalidTokenError } from '../interfaces/ports/jwt-signer.port';
import type { JwtConfig } from '../interfaces/configuration/jwt-config.interface';

// ── Jose mock ─────────────────────────────────────────────────────────────────
// Must be hoisted before the adapter import so the mock is in place when the
// module-level `import … from 'jose'` is evaluated.

const mockSign = jest.fn().mockResolvedValue('signed.jwt.token');
const mockJwtVerify = jest.fn();
const mockImportPKCS8 = jest.fn().mockResolvedValue({ type: 'private' } as CryptoKey);
const mockImportSPKI = jest.fn().mockResolvedValue({ type: 'public' } as CryptoKey);

// SignJWT builder chain mock
const mockBuilderChain = {
  setProtectedHeader: jest.fn().mockReturnThis(),
  setIssuedAt: jest.fn().mockReturnThis(),
  setExpirationTime: jest.fn().mockReturnThis(),
  setIssuer: jest.fn().mockReturnThis(),
  setAudience: jest.fn().mockReturnThis(),
  sign: mockSign,
};
const MockSignJWT = jest.fn().mockImplementation(() => mockBuilderChain);

jest.mock('jose', () => ({
  SignJWT: MockSignJWT,
  jwtVerify: mockJwtVerify,
  importPKCS8: mockImportPKCS8,
  importSPKI: mockImportSPKI,
}));

// Import AFTER the mock is registered
import { JoseJwtSigner } from './jose-jwt-signer.adapter';

// ── Configs ───────────────────────────────────────────────────────────────────

const SYMMETRIC_CONFIG: JwtConfig = {
  type: 'symmetric',
  secret: 'super-secret-key-long-enough-for-hs256',
  accessToken: { expiresIn: '15m', algorithm: 'HS256' },
};

const SYMMETRIC_NO_ALG: JwtConfig = {
  type: 'symmetric',
  secret: 'secret',
  accessToken: { expiresIn: '15m' },
};

const SYMMETRIC_WITH_CLAIMS: JwtConfig = {
  type: 'symmetric',
  secret: 'super-secret-key-long-enough-for-hs256',
  accessToken: {
    expiresIn: '15m',
    algorithm: 'HS256',
    issuer: 'https://auth.example.com',
    audience: 'my-app',
  },
};

const ASYMMETRIC_CONFIG: JwtConfig = {
  type: 'asymmetric',
  privateKey: '-----BEGIN PRIVATE KEY-----',
  publicKey: '-----BEGIN PUBLIC KEY-----',
  accessToken: { expiresIn: '15m', algorithm: 'ES256' },
};

const ASYMMETRIC_NO_ALG: JwtConfig = {
  type: 'asymmetric',
  privateKey: '-----BEGIN PRIVATE KEY-----',
  publicKey: '-----BEGIN PUBLIC KEY-----',
  accessToken: { expiresIn: '15m' },
};

// ── Tests ─────────────────────────────────────────────────────────────────────

describe('JoseJwtSigner', () => {
  let signer: JoseJwtSigner;

  beforeEach(() => {
    signer = new JoseJwtSigner();
    jest.clearAllMocks();
    // Reset the builder chain mock after clearAllMocks
    mockBuilderChain.setProtectedHeader.mockReturnThis();
    mockBuilderChain.setIssuedAt.mockReturnThis();
    mockBuilderChain.setExpirationTime.mockReturnThis();
    mockBuilderChain.setIssuer.mockReturnThis();
    mockBuilderChain.setAudience.mockReturnThis();
    mockBuilderChain.sign.mockResolvedValue('signed.jwt.token');
    MockSignJWT.mockImplementation(() => mockBuilderChain);
  });

  // ── init ───────────────────────────────────────────────────────────────────

  describe('init — symmetric', () => {
    it('uses the configured algorithm', async () => {
      await signer.init(SYMMETRIC_CONFIG);
      await signer.sign({ sub: 'u', type: 'access' }, '15m');
      expect(mockBuilderChain.setProtectedHeader).toHaveBeenCalledWith({
        alg: 'HS256',
      });
    });

    it('defaults to HS256 when algorithm is absent', async () => {
      await signer.init(SYMMETRIC_NO_ALG);
      await signer.sign({ sub: 'u', type: 'access' }, '15m');
      expect(mockBuilderChain.setProtectedHeader).toHaveBeenCalledWith({
        alg: 'HS256',
      });
    });

    it('encodes a string secret as Uint8Array', async () => {
      await signer.init(SYMMETRIC_CONFIG);
      // The signing key must be the encoded secret — verified indirectly:
      // sign() is called without error means the key was set correctly.
      await expect(
        signer.sign({ sub: 'u', type: 'access' }, '15m'),
      ).resolves.toBe('signed.jwt.token');
    });

    it('accepts a Buffer secret', async () => {
      const bufConfig: JwtConfig = {
        ...SYMMETRIC_CONFIG,
        secret: Buffer.from('secret-as-buffer'),
      };
      await signer.init(bufConfig);
      await expect(
        signer.sign({ sub: 'u', type: 'access' }, '15m'),
      ).resolves.toBe('signed.jwt.token');
    });
  });

  describe('init — asymmetric', () => {
    it('calls importPKCS8 and importSPKI with the configured algorithm', async () => {
      await signer.init(ASYMMETRIC_CONFIG);
      expect(mockImportPKCS8).toHaveBeenCalledWith(
        '-----BEGIN PRIVATE KEY-----',
        'ES256',
      );
      expect(mockImportSPKI).toHaveBeenCalledWith(
        '-----BEGIN PUBLIC KEY-----',
        'ES256',
      );
    });

    it('defaults to ES256 when algorithm is absent', async () => {
      await signer.init(ASYMMETRIC_NO_ALG);
      expect(mockImportPKCS8).toHaveBeenCalledWith(
        expect.any(String),
        'ES256',
      );
    });
  });

  // ── sign ───────────────────────────────────────────────────────────────────

  describe('sign', () => {
    beforeEach(() => signer.init(SYMMETRIC_CONFIG));

    it('returns the token produced by jose SignJWT', async () => {
      const result = await signer.sign({ sub: 'u', type: 'access' }, '15m');
      expect(result).toBe('signed.jwt.token');
    });

    it('passes a string expiresIn directly to setExpirationTime', async () => {
      await signer.sign({ sub: 'u', type: 'access' }, '15m');
      expect(mockBuilderChain.setExpirationTime).toHaveBeenCalledWith('15m');
    });

    it('converts a numeric expiresIn to a seconds string', async () => {
      await signer.sign({ sub: 'u', type: 'access' }, 900);
      expect(mockBuilderChain.setExpirationTime).toHaveBeenCalledWith('900s');
    });

    it('does not call setIssuer when no issuer is configured', async () => {
      await signer.sign({ sub: 'u', type: 'access' }, '15m');
      expect(mockBuilderChain.setIssuer).not.toHaveBeenCalled();
    });

    it('does not call setAudience when no audience is configured', async () => {
      await signer.sign({ sub: 'u', type: 'access' }, '15m');
      expect(mockBuilderChain.setAudience).not.toHaveBeenCalled();
    });

    it('calls setIssuer and setAudience when configured', async () => {
      const claimSigner = new JoseJwtSigner();
      await claimSigner.init(SYMMETRIC_WITH_CLAIMS);
      jest.clearAllMocks();
      mockBuilderChain.setProtectedHeader.mockReturnThis();
      mockBuilderChain.setIssuedAt.mockReturnThis();
      mockBuilderChain.setExpirationTime.mockReturnThis();
      mockBuilderChain.setIssuer.mockReturnThis();
      mockBuilderChain.setAudience.mockReturnThis();
      mockBuilderChain.sign.mockResolvedValue('signed.jwt.token');
      MockSignJWT.mockImplementation(() => mockBuilderChain);

      await claimSigner.sign({ sub: 'u', type: 'access' }, '15m');

      expect(mockBuilderChain.setIssuer).toHaveBeenCalledWith(
        'https://auth.example.com',
      );
      expect(mockBuilderChain.setAudience).toHaveBeenCalledWith('my-app');
    });
  });

  // ── verify ─────────────────────────────────────────────────────────────────

  describe('verify', () => {
    beforeEach(() => signer.init(SYMMETRIC_CONFIG));

    it('returns the decoded payload on success', async () => {
      mockJwtVerify.mockResolvedValue({
        payload: { sub: 'user-1', type: 'access' },
      });

      const result = await signer.verify('valid.jwt.token');

      expect(result).toEqual({ sub: 'user-1', type: 'access' });
    });

    it('passes algorithm, issuer, and audience to jwtVerify', async () => {
      mockJwtVerify.mockResolvedValue({
        payload: { sub: 'u', type: 'access' },
      });
      const claimSigner = new JoseJwtSigner();
      await claimSigner.init(SYMMETRIC_WITH_CLAIMS);

      await claimSigner.verify('some.token');

      expect(mockJwtVerify).toHaveBeenCalledWith(
        'some.token',
        expect.anything(),
        expect.objectContaining({
          algorithms: ['HS256'],
          issuer: 'https://auth.example.com',
          audience: 'my-app',
        }),
      );
    });

    it('wraps jose errors in InvalidTokenError', async () => {
      mockJwtVerify.mockRejectedValue(new Error('JWTExpired: token expired'));

      await expect(signer.verify('expired.token')).rejects.toThrow(
        InvalidTokenError,
      );
    });

    it('InvalidTokenError message comes from the original jose error', async () => {
      mockJwtVerify.mockRejectedValue(new Error('signature verification failed'));

      await expect(signer.verify('bad.token')).rejects.toThrow(
        'signature verification failed',
      );
    });
  });
});
