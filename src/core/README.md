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
- Export `AuthService`, `JwtAuthGuard`, `HashService`, and (when enabled)
  `GoogleOAuthGuard` so host modules can inject them without re-importing.

Decorated `@Global()` — register it once at the app root.

### `auth.service.ts` — `AuthService`

The **single orchestrator** for all authentication use-cases.

| Method | Capability | Description |
|---|---|---|
| `loginWithCredentials(input)` | credentials | Verify email + password, issue tokens |
| `register(input)` | credentials | Create user, hash password, issue tokens |
| `handleGoogleCallback(requestUser)` | google | Issue tokens after Passport sets `req.user` |
| `rotateRefreshToken(plainToken)` | refresh tokens | Validate, consume, re-issue token pair |
| `logout(userId)` | refresh tokens | Revoke all refresh tokens for a user |
| `changePassword(input)` | credentials | Change password (requires current password) |
| `setPassword(input)` | credentials | Force-set password (admin / reset flow) |
| `verifyEmail(userId)` | credentials | Mark email as verified |

### What `AuthService` does NOT do

- No authorisation checks (roles, permissions, policies).
- No email delivery — call `verifyEmail()` after your own token validation.
- No session management.

### Token issuance internals

Access tokens are signed JWTs (via `jose`). Refresh tokens are opaque,
high-entropy random strings stored as SHA-256 hashes — one-time-use
enforced at the DB level through `IRefreshTokenRepository`.

Keys are imported from `JwtConfig` once at `onModuleInit` and reused,
avoiding per-request key parsing overhead.
