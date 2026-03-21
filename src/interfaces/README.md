# src/interfaces/

**Ports and domain contracts.** This is the only layer with zero framework
or external library dependencies — every file is plain TypeScript.

## Sub-directories

### `ports/`
Internal ports that invert dependencies on external npm packages.
The core layer depends on these; adapters implement them.

| Port | Default adapter | Swappable via |
|---|---|---|
| `IJwtSigner` | `JoseJwtSigner` (jose) | `jwtSigner:` in `forRootAsync()` |
| `IPasswordHasher` | `Argon2PasswordHasher` (argon2) | `passwordHasher:` in `forRootAsync()` |
| `ITokenHasher` | `CryptoTokenHasher` (node:crypto) | `tokenHasher:` in `forRootAsync()` |
| `ITokenExtractor` | `BearerTokenExtractor` (Authorization header) | `tokenExtractor:` in `forRootAsync()` |
| `ILogger` | `ConsoleLogger` (console.log / console.error) | `logger:` in `forRootAsync()` |

### `configuration/`
Config shapes passed to `AuthModule.forRootAsync()`.

| File | Purpose |
|---|---|
| `jwt-config.interface.ts` | `JwtConfig` — symmetric vs asymmetric, access + refresh TTLs |
| `google-oauth-config.interface.ts` | `GoogleOAuthConfig` — clientID, secret, callbackURL |
| `auth-module-config.interface.ts` | `AuthModuleConfig` — the pure domain config object |

Note: `AuthModuleAsyncOptions` (the NestJS wiring type) lives in
`core/auth.module.ts` alongside `forRootAsync()`, not here, because it
imports NestJS types and belongs in the adapter layer.

### `user-model/`
Contracts for user entities and their repository.

| File | Purpose |
|---|---|
| `user.interface.ts` | `AuthUser`, `BaseUser`, `CredentialsUser`, `GoogleUser` |
| `request-user.interface.ts` | `RequestUser` — what lands on `req.user` after JWT validation |
| `authenticated-request.interface.ts` | Minimal `{ user: RequestUser }` — framework-agnostic, no Express import |
| `user-repository.interface.ts` | `IUserRepository` + `IGoogleUserRepository` — implement these |

### `refresh-token/`
Contracts for refresh token persistence.

| File | Purpose |
|---|---|
| `refresh-token.interface.ts` | `IRefreshToken` entity shape + `IRefreshTokenRepository` port |

### `authentication/`
Token and response types returned to callers.

| File | Purpose |
|---|---|
| `jwt-payload.interface.ts` | `JwtPayload` — `{ sub, type: 'access' }` |
| `auth-response.interface.ts` | `AuthResponse` + `TokenPair` |

### `operation-contracts/`
Input shapes for each auth operation — import these in your DTOs/controllers.

| Export | Purpose |
|---|---|
| `LoginInput` | `{ email, password }` |
| `RegistrationInput` | `{ email, password }` |
| `PasswordChangeInput` | `{ userId, currentPassword, newPassword }` |
| `PasswordSetInput` | `{ userId, newPassword }` |

## Rule

**Nothing in `interfaces/` may import from any other layer of this module,
from any adapter, or from any external library.**
It is the dependency inversion anchor — everything else depends on it.
