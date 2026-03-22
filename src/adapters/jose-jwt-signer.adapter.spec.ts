import { JoseJwtSigner } from './jose-jwt-signer.adapter';
import { InvalidTokenError } from '../interfaces/ports/jwt-signer.port';
import type { JwtConfig } from '../interfaces/configuration/jwt-config.interface';

const SYMMETRIC_CONFIG: JwtConfig = {
  type: 'symmetric',
  secret: 'super-secret-key-long-enough-for-hs256',
  accessToken: { expiresIn: '15m', algorithm: 'HS256' },
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

describe('JoseJwtSigner', () => {
  describe('with symmetric config (HS256)', () => {
    let signer: JoseJwtSigner;

    beforeEach(async () => {
      signer = new JoseJwtSigner();
      await signer.init(SYMMETRIC_CONFIG);
    });

    describe('sign', () => {
      it('returns a compact JWT string (three dot-separated parts)', async () => {
        const token = await signer.sign(
          { sub: 'user-1', type: 'access' },
          '15m',
        );
        const parts = token.split('.');
        expect(parts).toHaveLength(3);
      });

      it('embeds the sub and type claims', async () => {
        const token = await signer.sign(
          { sub: 'user-42', type: 'access' },
          '15m',
        );
        const payload = JSON.parse(
          Buffer.from(token.split('.')[1]!, 'base64url').toString(),
        );
        expect(payload.sub).toBe('user-42');
        expect(payload.type).toBe('access');
      });

      it('accepts a numeric expiresIn (seconds)', async () => {
        const token = await signer.sign({ sub: 'u', type: 'access' }, 900);
        expect(token.split('.')).toHaveLength(3);
      });
    });

    describe('verify', () => {
      it('returns the decoded payload for a valid token', async () => {
        const token = await signer.sign(
          { sub: 'user-1', type: 'access' },
          '15m',
        );
        const payload = await signer.verify(token);
        expect(payload.sub).toBe('user-1');
        expect(payload.type).toBe('access');
      });

      it('throws InvalidTokenError for an expired token', async () => {
        // Sign with a 1-second expiry then wait for it to lapse.
        const token = await signer.sign({ sub: 'u', type: 'access' }, 1);
        await new Promise((r) => setTimeout(r, 1100));
        await expect(signer.verify(token)).rejects.toThrow(InvalidTokenError);
      });

      it('throws InvalidTokenError for a token signed with a different secret', async () => {
        const otherSigner = new JoseJwtSigner();
        await otherSigner.init({
          ...SYMMETRIC_CONFIG,
          secret: 'completely-different-secret-key',
        });
        const foreignToken = await otherSigner.sign(
          { sub: 'u', type: 'access' },
          '15m',
        );
        await expect(signer.verify(foreignToken)).rejects.toThrow(
          InvalidTokenError,
        );
      });

      it('throws InvalidTokenError for a malformed token string', async () => {
        await expect(signer.verify('not.a.jwt')).rejects.toThrow(
          InvalidTokenError,
        );
      });
    });

    describe('issuer and audience validation', () => {
      let strictSigner: JoseJwtSigner;

      beforeEach(async () => {
        strictSigner = new JoseJwtSigner();
        await strictSigner.init(SYMMETRIC_WITH_CLAIMS);
      });

      it('verifies a token with matching issuer and audience', async () => {
        const token = await strictSigner.sign(
          { sub: 'u', type: 'access' },
          '15m',
        );
        const payload = await strictSigner.verify(token);
        expect(payload.sub).toBe('u');
      });

      it('rejects a token when issuer does not match', async () => {
        // Create a signer without issuer, produce a token, then verify
        // with the strict signer that requires a specific issuer.
        const relaxedSigner = new JoseJwtSigner();
        await relaxedSigner.init(SYMMETRIC_CONFIG);
        const token = await relaxedSigner.sign(
          { sub: 'u', type: 'access' },
          '15m',
        );
        await expect(strictSigner.verify(token)).rejects.toThrow(
          InvalidTokenError,
        );
      });
    });
  });

  describe('init', () => {
    it('defaults to HS256 for symmetric configs without explicit algorithm', async () => {
      const signer = new JoseJwtSigner();
      const config: JwtConfig = {
        type: 'symmetric',
        secret: 'long-enough-secret-for-hs256-signing',
        accessToken: { expiresIn: '15m' }, // no algorithm
      };
      await signer.init(config);

      const token = await signer.sign({ sub: 'u', type: 'access' }, '15m');
      const header = JSON.parse(
        Buffer.from(token.split('.')[0]!, 'base64url').toString(),
      );
      expect(header.alg).toBe('HS256');
    });
  });
});

describe('with asymmetric config (ES256)', () => {
  let signer: JoseJwtSigner;

  // Generate a real ES256 key pair once for this entire describe block.
  beforeAll(async () => {
    const { generateKeyPair, exportPKCS8, exportSPKI } = await import('jose');
    const { privateKey, publicKey } = await generateKeyPair('ES256');
    const privateKeyPem = await exportPKCS8(privateKey);
    const publicKeyPem = await exportSPKI(publicKey);

    signer = new JoseJwtSigner();
    await signer.init({
      type: 'asymmetric',
      privateKey: privateKeyPem,
      publicKey: publicKeyPem,
      accessToken: { expiresIn: '15m', algorithm: 'ES256' },
    });
  });

  it('signs and verifies a token round-trip', async () => {
    const token = await signer.sign(
      { sub: 'user-es256', type: 'access' },
      '15m',
    );
    const payload = await signer.verify(token);

    expect(payload.sub).toBe('user-es256');
    expect(payload.type).toBe('access');
  });

  it('uses ES256 in the token header', async () => {
    const token = await signer.sign({ sub: 'u', type: 'access' }, '15m');
    const header = JSON.parse(
      Buffer.from(token.split('.')[0]!, 'base64url').toString(),
    );
    expect(header.alg).toBe('ES256');
  });

  it('rejects a token signed with a different key pair', async () => {
    const { generateKeyPair, exportPKCS8, exportSPKI } = await import('jose');
    const { privateKey: otherPriv, publicKey: otherPub } =
      await generateKeyPair('ES256');
    const otherSigner = new JoseJwtSigner();
    await otherSigner.init({
      type: 'asymmetric',
      privateKey: await exportPKCS8(otherPriv),
      publicKey: await exportSPKI(otherPub),
      accessToken: { expiresIn: '15m', algorithm: 'ES256' },
    });

    const foreignToken = await otherSigner.sign(
      { sub: 'u', type: 'access' },
      '15m',
    );
    await expect(signer.verify(foreignToken)).rejects.toThrow(
      InvalidTokenError,
    );
  });
});
