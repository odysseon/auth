# src/core/

The **use-case layer** — the heart of the module.

## Files

### `auth.module.ts` — `AuthModule`

The dynamic root module. Consumers register it once via `forRootAsync()`.

Responsibilities:
- Accept configuration, repository classes, and capability flags.
- Register all internal providers with the correct DI tokens.
- Conditionally wire Google strategy/guard only when `'google'` is listed
  in `enabledCapabilities`.
- Export `AuthService`, `JwtAuthGuard`, and (when enabled) `GoogleOAuthGuard`
  so host modules can inject them without re-importing.

Decorated `@Global()` — register it once at the app root.

### `auth.service.ts` — `AuthService`

The **single orchestrator** for all authentication use-cases.

| Method | Capability | Description |
|---|---|---|
| `loginWithCredentials(input)` | credentials | Verify email + password, issue tokens |
| `register(input)` | credentials | Create user, hash password, issue tokens |
| `handleGoogleCallback(requestUser)` | google | Issue tokens after Passport sets `req.user` |
| `rotateRefreshToken(plainToken)` | refresh tokens | Atomically validate, consume, re-issue token pair |
| `logout(userId)` | refresh tokens | Revoke all refresh tokens for a user |
| `changePassword(input)` | credentials | Change password (requires current password) |
| `setPassword(input)` | credentials | Force-set password (admin / reset flow) |
| `verifyAccessToken(token)` | any | Verify a Bearer token (for custom guards) |

### What `AuthService` does NOT do

- No authorisation checks (roles, permissions, policies).
- No email delivery.
- No session management.

### Token issuance internals

Access tokens are signed JWTs (via `IJwtSigner`/`JoseJwtSigner`). Refresh
tokens are opaque, high-entropy random strings stored as SHA-256 hashes.
One-time-use is enforced by the atomic `consumeByTokenHash` method on
`IRefreshTokenRepository` — a single `DELETE … RETURNING *` prevents two
concurrent rotation requests from both succeeding with the same token.

Keys are imported from `JwtConfig` once at `onModuleInit` and reused,
avoiding per-request key parsing overhead.
