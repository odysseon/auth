/**
 * Shared sign options applied to every token issued.
 * `expiresIn` is required — never issue immortal tokens.
 */
export interface TokenSignOptions {
  /** e.g. '15m', '7d', or seconds as a number */
  expiresIn: string | number;
  /** JWT algorithm. Defaults: 'ES256' (asymmetric) or 'HS256' (symmetric). */
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
  /** Omit to disable refresh tokens. */
  refreshToken?: RefreshTokenConfig;
}

/** Asymmetric key config (ES256 / RS256 / etc.). */
export interface AsymmetricJwtConfig {
  type: 'asymmetric';
  privateKey: string | Buffer;
  publicKey: string | Buffer;
  accessToken: TokenSignOptions;
  /** Omit to disable refresh tokens. */
  refreshToken?: RefreshTokenConfig;
}

export type JwtConfig = SymmetricJwtConfig | AsymmetricJwtConfig;

/** Opaque token config for refresh tokens (not JWTs — stored hashes). */
export interface RefreshTokenConfig {
  /** Lifetime expressed as seconds or a string like '7d'. */
  expiresIn: string | number;
  /** Byte length of the random token before hashing. Default: 32. */
  tokenLength?: number;
}

// ── Type guards ────────────────────────────────────────────────────────────

export function isSymmetric(cfg: JwtConfig): cfg is SymmetricJwtConfig {
  return cfg.type === 'symmetric';
}

export function isAsymmetric(cfg: JwtConfig): cfg is AsymmetricJwtConfig {
  return cfg.type === 'asymmetric';
}

// ── Validation helper ──────────────────────────────────────────────────────

/**
 * Called at module initialisation to catch misconfiguration early.
 * Throws a descriptive `Error` rather than letting a cryptic runtime failure
 * surface later during a request.
 */
export function validateJwtConfig(cfg: JwtConfig): void {
  if (!cfg.accessToken?.expiresIn) {
    throw new Error(
      '[nestjs-auth-module] jwt.accessToken.expiresIn is required — ' +
        'never issue immortal access tokens.',
    );
  }

  if (cfg.type === 'symmetric') {
    if (!cfg.secret) {
      throw new Error(
        '[nestjs-auth-module] jwt.secret is required for symmetric config.',
      );
    }
  } else {
    if (!cfg.privateKey || !cfg.publicKey) {
      throw new Error(
        '[nestjs-auth-module] jwt.privateKey and jwt.publicKey are both ' +
          'required for asymmetric config.',
      );
    }
  }
}
