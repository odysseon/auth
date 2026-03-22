/**
 * Sign options applied to every access token issued.
 * `expiresIn` is required — immortal tokens are never acceptable.
 */
export interface TokenSignOptions {
  /** Duration string (e.g. `'15m'`, `'7d'`) or seconds as a number. */
  expiresIn: string | number;
  /**
   * JWT algorithm identifier.
   * Defaults to `'ES256'` for asymmetric configs and `'HS256'` for symmetric.
   * Must be a value accepted by your `IJwtSigner` adapter.
   */
  algorithm?: string;
  /** `iss` claim — strongly recommended in multi-service environments. */
  issuer?: string;
  /** `aud` claim */
  audience?: string | string[];
}

/** Symmetric key config (HS256 / HS384 / HS512). */
export interface SymmetricJwtConfig {
  type: 'symmetric';
  secret: string | Buffer;
  accessToken: TokenSignOptions;
  /** Omit to disable refresh token issuance entirely. */
  refreshToken?: RefreshTokenConfig;
}

/** Asymmetric key config (ES256 / RS256 / PS256 / etc.). */
export interface AsymmetricJwtConfig {
  type: 'asymmetric';
  privateKey: string | Buffer;
  publicKey: string | Buffer;
  accessToken: TokenSignOptions;
  /** Omit to disable refresh token issuance entirely. */
  refreshToken?: RefreshTokenConfig;
}

export type JwtConfig = SymmetricJwtConfig | AsymmetricJwtConfig;

/**
 * Configuration for opaque refresh tokens.
 * Refresh tokens are random byte strings stored as SHA-256 hashes — they are
 * not JWTs and carry no claims of their own.
 */
export interface RefreshTokenConfig {
  /**
   * Lifetime of each issued refresh token.
   * Accepts a duration string (`'7d'`, `'2w'`) or seconds as a number.
   */
  expiresIn: string | number;
  /**
   * Entropy of the generated plaintext token in bytes.
   * Default: 32 bytes → 256 bits. Do not lower this below 16.
   */
  tokenLength?: number;
}

// ── Duration parsing ───────────────────────────────────────────────────────

/**
 * Convert a duration string (`'15m'`, `'7d'`, `'2w'`) or a raw number of
 * seconds into seconds as a number.
 *
 * Accepted unit suffixes: `s` (seconds), `m` (minutes), `h` (hours),
 * `d` (days), `w` (weeks).
 *
 * Exported so consumers building cleanup jobs or computing token TTLs
 * can reuse the same parsing logic used internally for `RefreshTokenConfig.expiresIn`.
 */
export function parseDurationToSeconds(value: string | number): number {
  if (typeof value === 'number') return value;
  const m = value.match(/^(\d+)([smhdw])$/);
  // Groups 1 and 2 are guaranteed present when the regex matches.
  if (!m || !m[1] || !m[2])
    throw new Error(`[@odysseon/auth] Invalid duration format: "${value}"`);
  const n = parseInt(m[1], 10);
  const multipliers: Record<string, number> = {
    s: 1,
    m: 60,
    h: 3600,
    d: 86400,
    w: 604800,
  };
  return n * (multipliers[m[2]] ?? /* istanbul ignore next */ 1);
}

// ── Type guards ────────────────────────────────────────────────────────────

export function isSymmetric(cfg: JwtConfig): cfg is SymmetricJwtConfig {
  return cfg.type === 'symmetric';
}

export function isAsymmetric(cfg: JwtConfig): cfg is AsymmetricJwtConfig {
  return cfg.type === 'asymmetric';
}

// ── Startup validation ─────────────────────────────────────────────────────

/**
 * Validates `JwtConfig` at module initialisation.
 *
 * Throws a descriptive `Error` for every detectable misconfiguration so that
 * bad config crashes the application at startup rather than silently producing
 * insecure tokens at request time.
 */
export function validateJwtConfig(cfg: JwtConfig): void {
  if (!cfg.accessToken?.expiresIn) {
    throw new Error(
      '[@odysseon/auth] jwt.accessToken.expiresIn is required — ' +
        'never issue immortal access tokens.',
    );
  }

  if (cfg.type === 'symmetric') {
    if (!cfg.secret) {
      throw new Error(
        '[@odysseon/auth] jwt.secret is required for symmetric config.',
      );
    }
  } else {
    if (!cfg.privateKey || !cfg.publicKey) {
      throw new Error(
        '[@odysseon/auth] jwt.privateKey and jwt.publicKey are both ' +
          'required for asymmetric config.',
      );
    }
  }

  if (
    cfg.refreshToken?.tokenLength !== undefined &&
    cfg.refreshToken.tokenLength < 16
  ) {
    throw new Error(
      '[@odysseon/auth] jwt.refreshToken.tokenLength must be at least 16 bytes ' +
        '(128 bits). Values below this threshold provide insufficient entropy.',
    );
  }
}
