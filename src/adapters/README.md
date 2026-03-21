# src/adapters/

Default implementations of the five internal ports. Every adapter in this
directory is **swappable** — pass a replacement class (or instance) to
`AuthModule.forRootAsync()` and the rest of the module is completely unaffected.

## Adapters

### `JoseJwtSigner` → `IJwtSigner`

Wraps the **jose** library for JWT signing and verification.

**Why jose?**
- Uses the Web Crypto API — hardware-acceleratable, FIPS-certifiable.
- Works in Node, Deno, Bun, and edge runtimes unchanged.
- Zero sub-dependencies.

**To swap:** Implement `IJwtSigner` and pass `jwtSigner: YourClass`.

```ts
// jsonwebtoken-signer.adapter.ts
@Injectable()
export class JsonwebtokenSigner implements IJwtSigner {
  async init(config: JwtConfig) { /* import key */ }
  async sign(payload, expiresIn) { return jwt.sign(payload, this.key, { expiresIn }); }
  async verify(token) { return jwt.verify(token, this.key) as JwtPayload; }
}

// AuthModule.forRootAsync({ jwtSigner: JsonwebtokenSigner, ... })
```

---

### `Argon2PasswordHasher` → `IPasswordHasher`

Wraps **argon2id** for password hashing.

argon2 is declared as an **optional** peer dependency — it is lazy-loaded
at runtime. Projects that use only Google OAuth never need it installed.

**To swap:** Implement `IPasswordHasher` and pass `passwordHasher: YourClass`.

```ts
// bcrypt-password-hasher.adapter.ts
@Injectable()
export class BcryptPasswordHasher implements IPasswordHasher {
  async hash(password: string)                 { return bcrypt.hash(password, 12); }
  async verify(password: string, hash: string) { return bcrypt.compare(password, hash); }
}

// AuthModule.forRootAsync({ passwordHasher: BcryptPasswordHasher, ... })
```

---

### `CryptoTokenHasher` → `ITokenHasher`

Wraps Node's built-in **`node:crypto`** module. No extra dependencies.

SHA-256 is used for hashing refresh tokens because the tokens being hashed
are already high-entropy random byte strings (256-bit default). A slow
password hashing function is unnecessary here and would add latency.

**To swap:** Implement `ITokenHasher` and pass `tokenHasher: YourClass`.

```ts
// kms-token-hasher.adapter.ts
@Injectable()
export class KmsTokenHasher implements ITokenHasher {
  hash(token: string)    { return kmsClient.hash(token); }
  generate(bytes = 32)   { return kmsClient.random(bytes); }
}

// AuthModule.forRootAsync({ tokenHasher: KmsTokenHasher, ... })
```

---

### `BearerTokenExtractor` → `ITokenExtractor`  *(default)*

Reads the JWT from the `Authorization: Bearer <token>` header. This is
`AuthModule`'s default — no configuration required for standard API setups.

Handles array-valued headers (some proxies forward repeated headers as arrays)
and guards against empty tokens (`"Bearer "` returns `null`).

**To swap:** Use `CookieTokenExtractor`, `QueryParamTokenExtractor`, or
implement `ITokenExtractor` and pass it as `tokenExtractor:`.

---

### `CookieTokenExtractor` → `ITokenExtractor`

Reads the JWT from a named HTTP cookie. Requires `cookie-parser` middleware
to be active in the host application.

```ts
// main.ts
import * as cookieParser from 'cookie-parser';
app.use(cookieParser());

// AuthModule.forRootAsync({ tokenExtractor: new CookieTokenExtractor('access_token'), ... })
```

---

### `QueryParamTokenExtractor` → `ITokenExtractor`

Reads the JWT from a URL query parameter.

Suitable for WebSocket handshakes, server-sent events, or file-download
links. **Avoid for standard API requests** — query parameters are logged by
most HTTP servers and proxies.

```ts
// AuthModule.forRootAsync({ tokenExtractor: new QueryParamTokenExtractor('token'), ... })
// → reads ?token=<jwt> from the URL
```

---

### `ConsoleLogger` → `ILogger`  *(default)*

Writes informational messages to `console.log` and errors to `console.error`.

**Zero external dependencies** — no `@nestjs/common`, no logging framework.
Works in plain Node.js, NestJS, Fastify, Lambda, or any other runtime.

**To swap:** Implement `ILogger` and pass `logger: YourClass`.

```ts
// nestjs-logger.adapter.ts
import { Logger } from '@nestjs/common';

@Injectable()
export class NestJsLogger implements ILogger {
  private readonly l = new Logger('AuthService');
  log(message: string)                  { this.l.log(message); }
  error(message: string, ctx?: unknown) { this.l.error(message, ctx); }
}

// AuthModule.forRootAsync({ logger: NestJsLogger, ... })
```

---

## Dependency direction

```
interfaces/ports/  (contracts — no deps)
      ↑
adapters/          (default implementations — depend on external libs or nothing)
      ↑
core/              (AuthModule wires ports → adapters via DI tokens)
```

The core never imports from adapters directly — it only knows about ports.
