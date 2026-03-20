import { BearerTokenExtractor } from './bearer-token-extractor.adapter';
import { CookieTokenExtractor } from './cookie-token-extractor.adapter';
import { QueryParamTokenExtractor } from './query-param-token-extractor.adapter';

// ── BearerTokenExtractor ──────────────────────────────────────────────────────

describe('BearerTokenExtractor', () => {
  let extractor: BearerTokenExtractor;

  beforeEach(() => {
    extractor = new BearerTokenExtractor();
  });

  describe('happy path', () => {
    it('returns the token from a well-formed Bearer header', () => {
      expect(
        extractor.extract({
          headers: { authorization: 'Bearer my.jwt.token' },
        }),
      ).toBe('my.jwt.token');
    });

    it('is case-insensitive for the Bearer scheme', () => {
      expect(
        extractor.extract({
          headers: { authorization: 'bearer my.jwt.token' },
        }),
      ).toBe('my.jwt.token');

      expect(
        extractor.extract({
          headers: { authorization: 'BEARER my.jwt.token' },
        }),
      ).toBe('my.jwt.token');
    });

    it('uses the first entry when the header is an array', () => {
      expect(
        extractor.extract({
          headers: {
            authorization: ['Bearer first.token', 'Bearer second.token'],
          },
        }),
      ).toBe('first.token');
    });
  });

  describe('null cases', () => {
    it('returns null when the request has no headers', () => {
      expect(extractor.extract({})).toBeNull();
    });

    it('returns null when the authorization header is absent', () => {
      expect(extractor.extract({ headers: {} })).toBeNull();
    });

    it('returns null when the authorization header is undefined', () => {
      expect(
        extractor.extract({ headers: { authorization: undefined } }),
      ).toBeNull();
    });

    it('returns null for a non-Bearer scheme', () => {
      expect(
        extractor.extract({ headers: { authorization: 'Basic dXNlcjpwYXNz' } }),
      ).toBeNull();
    });

    it('returns null when the token part is empty ("Bearer ")', () => {
      expect(
        extractor.extract({ headers: { authorization: 'Bearer ' } }),
      ).toBeNull();
    });

    it('returns null when the header is only "Bearer" with no token', () => {
      expect(
        extractor.extract({ headers: { authorization: 'Bearer' } }),
      ).toBeNull();
    });

    it('returns null when the header value is a non-string after array unwrap', () => {
      // Simulates a framework that may place non-string values on headers.
      expect(
        extractor.extract({
          headers: { authorization: 42 as unknown as string },
        }),
      ).toBeNull();
    });

    it('returns null for a null request', () => {
      expect(extractor.extract(null)).toBeNull();
    });

    it('returns null for undefined request', () => {
      expect(extractor.extract(undefined)).toBeNull();
    });
  });
});

// ── CookieTokenExtractor ──────────────────────────────────────────────────────

describe('CookieTokenExtractor', () => {
  let extractor: CookieTokenExtractor;

  beforeEach(() => {
    extractor = new CookieTokenExtractor('access_token');
  });

  describe('happy path', () => {
    it('returns the cookie value when the named cookie is present', () => {
      expect(
        extractor.extract({ cookies: { access_token: 'my.jwt.token' } }),
      ).toBe('my.jwt.token');
    });

    it('uses the configured cookie name', () => {
      const custom = new CookieTokenExtractor('auth');
      expect(
        custom.extract({ cookies: { auth: 'tok', access_token: 'other' } }),
      ).toBe('tok');
    });
  });

  describe('null cases', () => {
    it('returns null when the cookies object is absent', () => {
      expect(extractor.extract({})).toBeNull();
    });

    it('returns null when the named cookie is not set', () => {
      expect(extractor.extract({ cookies: { other: 'val' } })).toBeNull();
    });

    it('returns null when the named cookie is undefined', () => {
      expect(
        extractor.extract({ cookies: { access_token: undefined } }),
      ).toBeNull();
    });

    it('returns null for a null request', () => {
      expect(extractor.extract(null)).toBeNull();
    });

    it('returns null for undefined request', () => {
      expect(extractor.extract(undefined)).toBeNull();
    });
  });
});

// ── QueryParamTokenExtractor ──────────────────────────────────────────────────

describe('QueryParamTokenExtractor', () => {
  let extractor: QueryParamTokenExtractor;

  beforeEach(() => {
    extractor = new QueryParamTokenExtractor('token');
  });

  describe('happy path — string value', () => {
    it('returns the param value when it is a non-empty string', () => {
      expect(extractor.extract({ query: { token: 'my.jwt.token' } })).toBe(
        'my.jwt.token',
      );
    });

    it('uses the configured param name', () => {
      const custom = new QueryParamTokenExtractor('access_token');
      expect(
        custom.extract({ query: { access_token: 'tok', token: 'other' } }),
      ).toBe('tok');
    });
  });

  describe('happy path — array value', () => {
    it('returns the first element when the param is a non-empty string array', () => {
      expect(
        extractor.extract({
          query: { token: ['first.token', 'second.token'] },
        }),
      ).toBe('first.token');
    });
  });

  describe('null cases — string value', () => {
    it('returns null when the param value is an empty string', () => {
      expect(extractor.extract({ query: { token: '' } })).toBeNull();
    });

    it('returns null when the param is absent', () => {
      expect(extractor.extract({ query: {} })).toBeNull();
    });

    it('returns null when the param is undefined', () => {
      expect(extractor.extract({ query: { token: undefined } })).toBeNull();
    });
  });

  describe('null cases — array value', () => {
    it('returns null when the array is empty', () => {
      expect(extractor.extract({ query: { token: [] } })).toBeNull();
    });

    it('returns null when the first array element is an empty string', () => {
      expect(extractor.extract({ query: { token: [''] } })).toBeNull();
    });

    it('returns null when the first array element is not a string', () => {
      expect(
        extractor.extract({ query: { token: [42 as unknown as string] } }),
      ).toBeNull();
    });
  });

  describe('null cases — unexpected types', () => {
    it('returns null when the value is a number', () => {
      expect(
        extractor.extract({ query: { token: 42 as unknown as string } }),
      ).toBeNull();
    });

    it('returns null when the query object is absent', () => {
      expect(extractor.extract({})).toBeNull();
    });

    it('returns null for a null request', () => {
      expect(extractor.extract(null)).toBeNull();
    });

    it('returns null for undefined request', () => {
      expect(extractor.extract(undefined)).toBeNull();
    });
  });
});
