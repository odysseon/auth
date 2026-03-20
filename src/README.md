# src/

Source root for `@odysseon/auth`.

## Layer map

```
src/
├── index.ts              ← Public API surface (only import from here)
│
├── interfaces/           ← Ports & domain types (zero framework or library deps)
│   └── ports/            ← Internal ports: IJwtSigner, IPasswordHasher, ITokenHasher, ITokenExtractor
├── constants/            ← DI injection tokens (Symbols)
├── adapters/             ← Default implementations of the four internal ports
├── core/                 ← AuthModule + AuthService (use-case layer)
├── strategies/           ← Passport strategies (JWT, Google)
├── guards/               ← JwtAuthGuard, GoogleOAuthGuard
└── decorators/           ← @CurrentUser(), @Public()
```

## Dependency direction

```
interfaces/ports/  (contracts — zero deps)
       ↑
  adapters/        (wrap external libs: jose, argon2, node:crypto, and header/cookie/query parsing)
       ↑
   core/ ──────────────────────────────────────── strategies/
(AuthModule wires                           (inject ports by token,
 ports → adapters,                           never libs directly)
 AuthService uses ports)
       ↑
   guards/ / decorators/
```

**Nothing above `interfaces/` is imported by anything below it.**
`AuthService` and `JwtStrategy` depend only on port interfaces — never on
`jose`, `argon2`, or any other external library directly.

## Swapping an external library

Pick the port whose library you want to replace, implement the interface,
and pass the class to `AuthModule.forRootAsync()`:

```ts
AuthModule.forRootAsync({
  jwtSigner:      JsonwebtokenSigner,   // replaces JoseJwtSigner (jose)
  passwordHasher: BcryptPasswordHasher, // replaces Argon2PasswordHasher (argon2)
  tokenHasher:    KmsTokenHasher,       // replaces CryptoTokenHasher (node:crypto)
  tokenExtractor: new CookieTokenExtractor('access_token'), // replaces BearerTokenExtractor
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
6. Re-export from `src/index.ts`.
