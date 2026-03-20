import 'reflect-metadata';
import { UnauthorizedException } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';
import type { JwtConfig } from '../interfaces';
import type { ITokenExtractor } from '../interfaces/ports/token-extractor.port';

/**
 * JwtStrategy.validate() is a plain method — we test it directly without
 * spinning up a Passport pipeline. The constructor wiring to passport-jwt
 * is covered by the e2e integration test.
 *
 * The extractor is injected into the constructor but is only exercised by
 * passport-jwt at request time, so a no-op stub is sufficient here.
 */
describe('JwtStrategy', () => {
  const stubExtractor: ITokenExtractor = {
    extract: () => null,
  };

  function makeStrategy(config: JwtConfig): JwtStrategy {
    return new JwtStrategy(config, stubExtractor);
  }

  const SYMMETRIC_CONFIG: JwtConfig = {
    type: 'symmetric',
    secret: 'test-secret',
    accessToken: { expiresIn: '15m', algorithm: 'HS256' },
  };

  describe('validate', () => {
    let strategy: JwtStrategy;

    beforeEach(() => {
      strategy = makeStrategy(SYMMETRIC_CONFIG);
    });

    it('returns RequestUser with userId from sub claim', () => {
      expect(strategy.validate({ sub: 'user-42', type: 'access' })).toEqual({
        userId: 'user-42',
      });
    });

    it('throws UnauthorizedException when sub is missing', () => {
      expect(() => strategy.validate({ sub: '', type: 'access' })).toThrow(
        UnauthorizedException,
      );
    });

    it('throws UnauthorizedException when type is not "access"', () => {
      // Simulates a refresh token being presented as an access token.
      expect(() =>
        strategy.validate({ sub: 'user-1', type: 'refresh' as 'access' }),
      ).toThrow(UnauthorizedException);
    });

    it('includes a descriptive message when token type is wrong', () => {
      expect(() =>
        strategy.validate({ sub: 'user-1', type: 'refresh' as 'access' }),
      ).toThrow('expected an access token');
    });
  });

  describe('validate — config type variants', () => {
    it('works with asymmetric config shape', () => {
      const strategy = makeStrategy({
        type: 'asymmetric',
        privateKey: 'priv',
        publicKey: 'pub',
        accessToken: { expiresIn: '15m', algorithm: 'ES256' },
      });

      expect(strategy.validate({ sub: 'user-1', type: 'access' })).toEqual({
        userId: 'user-1',
      });
    });

    it('works when algorithm is absent from config', () => {
      const strategy = makeStrategy({
        type: 'symmetric',
        secret: 'secret',
        accessToken: { expiresIn: '15m' }, // no algorithm
      });

      expect(strategy.validate({ sub: 'u', type: 'access' })).toEqual({
        userId: 'u',
      });
    });
  });

  describe('constructor — extractor integration', () => {
    it('calls extract on the provided ITokenExtractor when passport invokes jwtFromRequest', () => {
      const extract = jest.fn().mockReturnValue(null);
      const extractor: ITokenExtractor = { extract };
      const strategy = new JwtStrategy(SYMMETRIC_CONFIG, extractor);

      // Access the internal passport-jwt options to trigger jwtFromRequest.
      const jwtFromRequest = (strategy as any)._jwtFromRequest as (
        req: unknown,
      ) => string | null;
      const fakeReq = { headers: { authorization: 'Bearer tok' } };
      jwtFromRequest(fakeReq);

      expect(extract).toHaveBeenCalledWith(fakeReq);
    });
  });
});
