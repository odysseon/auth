# src/interfaces/ports/

**Internal ports** — the contracts between the core use-case layer and the
external libraries it depends on.

These ports exist specifically to invert the dependency direction on external
npm packages. The core (`AuthService`, `JwtStrategy`) imports from here;
it never imports `jose`, `argon2`, `crypto`, or `passport-jwt` directly.

## Ports

### `IPasswordHasher`
Abstracts the password hashing library.

| Method | Signature |
|---|---|
| `hash` | `(password: string) → Promise<string>` |
| `verify` | `(password: string, hash: string) → Promise<boolean>` |

Default adapter: `Argon2PasswordHasher` (argon2id)
Swap to: bcrypt, scrypt, PBKDF2

### `ITokenHasher`
Abstracts opaque token hashing and generation.

| Method | Signature |
|---|---|
| `hash` | `(token: string) → string` |
| `generate` | `(bytes?: number) → string` |

Default adapter: `CryptoTokenHasher` (Node built-in crypto)
Swap to: KMS, HSM, any CSPRNG source

### `IJwtSigner`
Abstracts the JWT library.

| Method | Signature |
|---|---|
| `init` | `(config: JwtConfig) → Promise<void>` |
| `sign` | `(payload: JwtPayload, expiresIn: string \| number) → Promise<string>` |
| `verify` | `(token: string) → Promise<JwtPayload>` |

Default adapter: `JoseJwtSigner` (jose)
Swap to: jsonwebtoken, fast-jwt, any JWT library

### `ITokenExtractor`
Abstracts how a JWT is extracted from an incoming HTTP request.

| Method | Signature |
|---|---|
| `extract` | `(request: unknown) → string \| null` |

`JwtStrategy` calls `tokenExtractor.extract(req)` and passes the result to
`passport-jwt` as `jwtFromRequest`. Return `null` to signal "no token" —
never throw.

Default adapter: `BearerTokenExtractor` (`Authorization: Bearer <token>`)
Swap to: `CookieTokenExtractor`, `QueryParamTokenExtractor`, or a custom implementation

### `ILogger`
Abstracts informational logging inside `AuthService`.

| Method | Signature |
|---|---|
| `log` | `(message: string) → void` |
| `error` | `(message: string, context?: unknown) → void` |

Default adapter: `ConsoleLogger` (zero deps — `console.log` / `console.error`)
Swap to: NestJS `Logger`, Pino, Winston, or any sink

`ConsoleLogger` has **no framework imports** — it is a plain class that works
in any Node.js runtime without NestJS installed.

## Rule

**Nothing in `ports/` may import from adapters or from any external library.**
Ports are pure TypeScript interfaces — they only reference types defined
in the rest of `interfaces/`.

## Swapping an adapter

```ts
AuthModule.forRootAsync({
  // ...
  jwtSigner:      MyJwtSigner,       // replaces JoseJwtSigner
  passwordHasher: MyPasswordHasher,  // replaces Argon2PasswordHasher
  tokenHasher:    MyTokenHasher,     // replaces CryptoTokenHasher
  tokenExtractor: MyTokenExtractor,  // replaces BearerTokenExtractor
  logger:         MyLogger,          // replaces ConsoleLogger
})
```

No other files need to change.
