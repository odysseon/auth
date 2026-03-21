# src/constants/

NestJS dependency-injection tokens for this module.

All tokens are `Symbol` values — they cannot clash with tokens in the host
application or with string tokens from other libraries.

## Tokens

### `AUTH_CONFIG`
The raw, fully-resolved `AuthModuleConfig` object returned by `useFactory`.
Consumed by the capability-slice providers to extract sub-configs.

### `AUTH_CAPABILITIES`

| Token | Injected value | Consumer |
|---|---|---|
| `AUTH_CAPABILITIES.JWT` | `JwtConfig` | `AuthService`, `JwtStrategy`, `JoseJwtSigner` |
| `AUTH_CAPABILITIES.GOOGLE` | `GoogleOAuthConfig` (or `null`) | `GoogleStrategy` |

Strategies and `AuthService` inject the relevant config slice rather than
the whole config object, so they stay narrowly scoped.

### `PORTS`

**Caller-supplied** (you implement these):

| Token | Interface | Purpose |
|---|---|---|
| `PORTS.USER_REPOSITORY` | `IUserRepository` | User persistence reads & writes |
| `PORTS.REFRESH_TOKEN_REPOSITORY` | `IRefreshTokenRepository` | Refresh token persistence (optional) |

**Internally defaulted** (swappable via `AuthModule.forRootAsync()`):

| Token | Interface | Default adapter | Swap option |
|---|---|---|---|
| `PORTS.JWT_SIGNER` | `IJwtSigner` | `JoseJwtSigner` | `jwtSigner: YourClass` |
| `PORTS.PASSWORD_HASHER` | `IPasswordHasher` | `Argon2PasswordHasher` | `passwordHasher: YourClass` |
| `PORTS.TOKEN_HASHER` | `ITokenHasher` | `CryptoTokenHasher` | `tokenHasher: YourClass` |
| `PORTS.TOKEN_EXTRACTOR` | `ITokenExtractor` | `BearerTokenExtractor` | `tokenExtractor: YourClass` |
| `PORTS.LOGGER` | `ILogger` | `ConsoleLogger` | `logger: YourClass` |

## Testing overrides

```ts
// Override any port in unit tests without changing production wiring:
{
  provide: PORTS.PASSWORD_HASHER,
  useValue: { hash: jest.fn(), verify: jest.fn().mockResolvedValue(true) },
}
{
  provide: PORTS.TOKEN_EXTRACTOR,
  useValue: { extract: jest.fn().mockReturnValue('mock-token') },
}
{
  provide: PORTS.LOGGER,
  useValue: { log: jest.fn(), error: jest.fn() },
}
```
