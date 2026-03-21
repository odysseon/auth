# src/core/

The **use-case layer** — the heart of the module.

## Files

### `auth.module.ts` — `AuthModule`

The dynamic root module. Consumers register it once via `forRootAsync()`.

Responsibilities:
- Accept configuration, repository classes, and capability flags.
- Register all internal providers with the correct DI tokens.
- Run `AuthService.init()` at startup via the internal `AuthInitializer` class
  (which implements `OnModuleInit` so `AuthService` itself does not need to).
- Conditionally wire Google strategy/guard only when `'google'` is listed
  in `enabledCapabilities`.
- Export `AuthService`, `JwtAuthGuard`, and (when enabled) `GoogleOAuthGuard`
  so host modules can inject them without re-importing.

Decorated `@Global()` — register it once at the app root.

### `auth.service.ts` — `AuthService`

The **single orchestrator** for all authentication use-cases.

`AuthService` is a plain class with no NestJS lifecycle coupling. It throws
`AuthError` with typed `AuthErrorCode` values — never HTTP exceptions. The
`AuthExceptionFilter` in `src/filters/` maps those codes to HTTP responses.

| Method | Capability | Description |
|---|---|---|
| `init()` | — | Validate config and initialise the JWT signer. Call once at startup. |
| `loginWithCredentials(input)` | credentials | Verify email + password, issue tokens |
| `register(input)` | credentials | Create user, hash password, issue tokens |
| `handleGoogleCallback(requestUser)` | google | Issue tokens after Passport sets `req.user` |
| `rotateRefreshToken(plainToken)` | refresh tokens | Atomically validate, consume, re-issue token pair |
| `logout(userId)` | refresh tokens | Revoke all refresh tokens for a user |
| `changePassword(input)` | credentials | Change password (requires current password) |
| `setPassword(input)` | credentials | Force-set password (admin / reset flow) |
| `verifyAccessToken(token)` | any | Verify a token (for custom guards) |

### What `AuthService` does NOT do

- Authorisation checks (roles, permissions, policies).
- Email delivery.
- Session management.
- HTTP response formatting — that is `AuthExceptionFilter`'s job.

### Token issuance internals

Access tokens are signed JWTs (via `IJwtSigner`/`JoseJwtSigner`). Refresh
tokens are opaque, high-entropy random strings stored as SHA-256 hashes.
One-time-use is enforced by the atomic `consumeByTokenHash` method on
`IRefreshTokenRepository` — a single `DELETE … RETURNING *` prevents two
concurrent rotation requests from both succeeding with the same token.

Keys are imported from `JwtConfig` once in `init()` and reused,
avoiding per-request key parsing overhead.
