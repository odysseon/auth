# src/

Source root for `@odysseon/auth`.

## Layer map

```
src/
├── index.ts              ← Public API surface (only import from here)
│
├── interfaces/           ← Ports & domain types (zero framework or library deps)
│   └── ports/            ← IJwtSigner, IPasswordHasher, ITokenHasher, ITokenExtractor, ILogger
├── errors/               ← AuthError + AuthErrorCode (zero deps — thrown by AuthService)
├── constants/            ← DI injection tokens (Symbols)
├── adapters/             ← Default implementations of the five internal ports
├── core/                 ← AuthModule + AuthService (use-case layer)
├── filters/              ← AuthExceptionFilter (NestJS HTTP adapter for AuthError)
├── strategies/           ← Passport strategies (JWT, Google)
├── guards/               ← JwtAuthGuard, GoogleOAuthGuard
├── decorators/           ← @CurrentUser(), @Public()
└── examples/             ← Reference-only code (excluded from dist/)
```

## Dependency direction

```
interfaces/ports/  (contracts — zero deps)
errors/            (AuthError — zero deps)
       ↑
  adapters/        (wrap external libs: jose, argon2, node:crypto, console)
       ↑
   core/ ──────────────────────────────────────── strategies/
(AuthModule wires                           (inject ports by token,
 ports → adapters,                           never libs directly)
 AuthService uses ports)
       ↑
   filters/ / guards/ / decorators/
```

**Nothing above `interfaces/` or `errors/` is imported by anything below it.**
`AuthService` throws `AuthError` (from `errors/`) — never NestJS HTTP exceptions.
`AuthExceptionFilter` (in `filters/`) is the only place that maps `AuthError` to HTTP.

## Swapping an external library

Pick the port whose library you want to replace, implement the interface,
and pass the class to `AuthModule.forRootAsync()`:

```ts
AuthModule.forRootAsync({
  jwtSigner:      JsonwebtokenSigner,   // replaces JoseJwtSigner (jose)
  passwordHasher: BcryptPasswordHasher, // replaces Argon2PasswordHasher (argon2)
  tokenHasher:    KmsTokenHasher,       // replaces CryptoTokenHasher (node:crypto)
  tokenExtractor: new CookieTokenExtractor('access_token'), // replaces BearerTokenExtractor
  logger:         NestJsLogger,         // replaces ConsoleLogger
  // ... rest of options
})
```

No other files change.

## Adding a new auth capability

1. Define its config shape in `interfaces/configuration/`.
2. Add a DI token in `constants/`.
3. Implement the strategy in `strategies/`.
4. Wire the token and strategy in `core/auth.module.ts`.
5. Add the use-case method(s) to `core/auth.service.ts`.
6. Add any new `AuthErrorCode` values to `errors/auth-error.ts`.
7. Re-export from `src/index.ts`.
