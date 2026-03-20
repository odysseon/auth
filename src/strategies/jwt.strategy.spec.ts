import 'reflect-metadata';
import { UnauthorizedException } from '@nestjs/common';
import { JwtStrategy } from './jwt.strategy';
import { AUTH_CAPABILITIES } from '../constants';
import type { JwtConfig } from '../interfaces';

/**
 * JwtStrategy.validate() is a plain method — we test it directly without
 * spinning up a Passport pipeline. The constructor wiring to passport-jwt
 * is covered by the e2e integration test.
 */
describe('JwtStrategy', () => {
  function makeStrategy(config: JwtConfig): JwtStrategy {
    const s = Object.create(JwtStrategy.prototype) as JwtStrategy;
    Reflect.defineMetadata(AUTH_CAPABILITIES.JWT, config, s);
    return s;
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
});
