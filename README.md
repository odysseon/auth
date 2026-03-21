# @odysseon/auth

A plug-and-play, identity-only NestJS authentication module built on
**hexagonal architecture**. It handles **who you are** — not what you're
allowed to do. Authorization is your application's concern.

## Requirements

- **Node.js >= 22**
- **pnpm >= 9**

## Design goals

- **Identity only.** No roles, no permissions, no RBAC.
- **Hexagonal architecture.** Ports define what the module needs; your app provides adapters.
- **ORM / DB agnostic.** Bring your own repository implementations.
- **Library agnostic.** Every external npm dependency sits behind a port.
  Swap `jose` → `jsonwebtoken`, `argon2` → `bcrypt`, `node:crypto` → a KMS,
  or `Bearer header` → a cookie by passing one class. Zero changes to core logic.
- **Capability flags.** Enable only the auth methods you need.
- **True refresh-token rotation.** One-time-use tokens, atomically consumed, SHA-256 hashed.
- **Framework-agnostic core.** `AuthService` is a plain class — use it with NestJS,
  plain Fastify, Express, Lambda, or any other runtime. The NestJS adapter layer
  (strategies, guards, decorators, module) is the only part that requires NestJS.

## Architecture

```
interfaces/ports/   ← contracts (zero deps — the inversion anchor)
      ↑
  adapters/         ← default implementations of the five internal ports
      ↑
    core/           ← AuthService + AuthModule (use-cases, wiring)
  strategies/       ← Passport strategies
  filters/          ← AuthExceptionFilter (NestJS HTTP adapter)
    guards/         ← JwtAuthGuard, GoogleOAuthGuard
 decorators/        ← @CurrentUser(), @Public()
```

### Swappable adapters

| Port | Interface | Default | Swap option |
|---|---|---|---|
| JWT signing/verification | `IJwtSigner` | `JoseJwtSigner` (jose) | `jwtSigner:` |
| Password hashing | `IPasswordHasher` | `Argon2PasswordHasher` (argon2id) | `passwordHasher:` |
| Token hashing / generation | `ITokenHasher` | `CryptoTokenHasher` (node:crypto) | `tokenHasher:` |
| JWT extraction from request | `ITokenExtractor` | `BearerTokenExtractor` (Authorization header) | `tokenExtractor:` |
| Logging | `ILogger` | `ConsoleLogger` (console.log / console.error) | `logger:` |

## Error handling

`AuthService` throws `AuthError` with a typed `AuthErrorCode` — never HTTP-specific
exceptions. This keeps the core framework-agnostic and gives consumers full control
over how errors are surfaced.

**NestJS users:** register `AuthExceptionFilter` to map error codes to HTTP responses:

```ts
// app.module.ts
providers: [
  { provide: APP_GUARD,  useClass: JwtAuthGuard },
  { provide: APP_FILTER, useClass: AuthExceptionFilter },
]
```

**Non-NestJS users:** catch `AuthError` and map `err.code` yourself:

```ts
import { AuthError, AuthErrorCode } from '@odysseon/auth';

try {
  await authService.loginWithCredentials(input);
} catch (err) {
  if (err instanceof AuthError) {
    switch (err.code) {
      case AuthErrorCode.INVALID_CREDENTIALS: return reply.status(401).send();
      case AuthErrorCode.EMAIL_ALREADY_EXISTS: return reply.status(409).send();
    }
  }
  throw err;
}
```

### Error code → HTTP status map

| `AuthErrorCode` | Default HTTP status | Thrown by |
|---|---|---|
| `INVALID_CREDENTIALS` | 401 | `loginWithCredentials`, `changePassword` (wrong current password) |
| `EMAIL_ALREADY_EXISTS` | 409 | `register` |
| `OAUTH_ACCOUNT_NO_PASSWORD` | 400 | `changePassword`, `setPassword` (OAuth-only account) |
| `PASSWORD_SAME_AS_OLD` | 400 | `changePassword` |
| `USER_NOT_FOUND` | 404 | `changePassword`, `setPassword`, `rotateRefreshToken` (deleted user) |
| `OAUTH_USER_NOT_FOUND` | 401 | `handleGoogleCallback` (user vanished after OAuth) |
| `REFRESH_TOKEN_INVALID` | 401 | `rotateRefreshToken` (bad/used token), `verifyAccessToken` |
| `REFRESH_TOKEN_EXPIRED` | 401 | `rotateRefreshToken` |
| `REFRESH_NOT_ENABLED` | 501 | `rotateRefreshToken` (misconfiguration) |

## Quick start

### 1. Install

```bash
pnpm add @odysseon/auth
# Peer deps
pnpm add @nestjs/passport passport passport-jwt
# Default adapter deps (install only what you use)
pnpm add jose                    # JWT — always needed
pnpm add argon2                  # passwords — needed for 'credentials' capability
pnpm add passport-google-oauth20 # needed for 'google' capability
```

### 2. Implement your repository ports

```ts
// user.repository.ts
@Injectable()
export class UserRepository implements IGoogleUserRepository<User> {
  findById(id: string)          { return this.db.users.findOne({ id }); }
  findByEmail(email: string)    { return this.db.users.findOne({ email }); }
  findByGoogleId(id: string)    { return this.db.users.findOne({ googleId: id }); }
  create(data: Partial<User>)   { return this.db.users.create(data); }
  update(id, data)              { return this.db.users.update(id, data); }
}

// refresh-token.repository.ts
@Injectable()
export class RefreshTokenRepository implements IRefreshTokenRepository {
  create(data)                           { ... }
  consumeByTokenHash(hash: string)       { ... } // atomic find-and-delete
  deleteAllForUser(userId: string)       { ... }
}
```

### 3. Register the module

```ts
// app.module.ts
AuthModule.forRootAsync({
  imports:  [ConfigModule],
  inject:   [ConfigService],
  useFactory: (cfg: ConfigService) => ({
    jwt: {
      type:         'asymmetric',
      privateKey:   cfg.get('JWT_PRIVATE_KEY'),
      publicKey:    cfg.get('JWT_PUBLIC_KEY'),
      accessToken:  { expiresIn: '15m', algorithm: 'ES256' },
      refreshToken: { expiresIn: '7d' },
    },
    google: {
      clientID:     cfg.get('GOOGLE_CLIENT_ID'),
      clientSecret: cfg.get('GOOGLE_CLIENT_SECRET'),
      callbackURL:  cfg.get('GOOGLE_CALLBACK_URL'),
    },
  }),
  userRepository:         UserRepository,
  refreshTokenRepository: RefreshTokenRepository,
  enabledCapabilities:    ['credentials', 'google'],
})
```

### 4. Use in controllers

```ts
@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Public()
  @Post('register')
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Public()
  @Post('login')
  login(@Body() dto: LoginDto) {
    return this.authService.loginWithCredentials(dto);
  }

  @Public()
  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  googleLogin() {}

  @Public()
  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  googleCallback(@Req() req: AuthenticatedRequest) {
    return this.authService.handleGoogleCallback(req.user);
  }

  @Public()
  @Post('refresh')
  refresh(@Body('refreshToken') token: string) {
    return this.authService.rotateRefreshToken(token);
  }

  @Post('logout')
  logout(@CurrentUser() user: RequestUser) {
    return this.authService.logout(user.userId);
  }

  @Get('me')
  me(@CurrentUser() user: RequestUser) {
    return user;
  }
}
```

### 5. Apply guard and filter globally (recommended)

```ts
// app.module.ts
providers: [
  { provide: APP_GUARD,  useClass: JwtAuthGuard },
  { provide: APP_FILTER, useClass: AuthExceptionFilter },
]
// Then use @Public() on open endpoints instead of @UseGuards everywhere.
```

## Swapping an adapter

No changes to any core file — only your module registration changes:

```ts
// swap-bcrypt.example.ts
import * as bcrypt from 'bcrypt';

@Injectable()
export class BcryptPasswordHasher implements IPasswordHasher {
  async hash(password: string)                 { return bcrypt.hash(password, 12); }
  async verify(password: string, hash: string) { return bcrypt.compare(password, hash); }
}

// In AuthModule.forRootAsync():
passwordHasher: BcryptPasswordHasher
```

### Swapping the token extractor

By default tokens are read from `Authorization: Bearer <token>`. To read from
a cookie instead:

```ts
import { CookieTokenExtractor } from '@odysseon/auth';

// In AuthModule.forRootAsync():
tokenExtractor: new CookieTokenExtractor('access_token')
```

Requires `cookie-parser` middleware in your application:

```ts
// main.ts
import * as cookieParser from 'cookie-parser';
app.use(cookieParser());
```

### Swapping the logger

By default informational messages are written to `console.log`. To use NestJS
structured logging:

```ts
import { Logger } from '@nestjs/common';
import type { ILogger } from '@odysseon/auth';

@Injectable()
export class NestJsLogger implements ILogger {
  private readonly l = new Logger('AuthService');
  log(message: string)                     { this.l.log(message); }
  error(message: string, ctx?: unknown)    { this.l.error(message, ctx); }
}

// In AuthModule.forRootAsync():
logger: NestJsLogger
```

## Testing

Every external dependency is behind a port — mock the token, not the library:

```ts
const module = await Test.createTestingModule({ ... })
  .overrideProvider(PORTS.PASSWORD_HASHER)
  .useValue({ hash: jest.fn().mockResolvedValue('hash'), verify: jest.fn().mockResolvedValue(true) })
  .overrideProvider(PORTS.JWT_SIGNER)
  .useValue({ init: jest.fn(), sign: jest.fn().mockResolvedValue('token'), verify: jest.fn() })
  .overrideProvider(PORTS.TOKEN_EXTRACTOR)
  .useValue({ extract: jest.fn().mockReturnValue('mock-token') })
  .overrideProvider(PORTS.LOGGER)
  .useValue({ log: jest.fn(), error: jest.fn() })
  .compile();
```

No real crypto runs in tests. Blazing fast, zero flakiness.

## Exported API

| Export | Description |
|---|---|
| `AuthModule` | Root module — `forRootAsync()` |
| `AuthModuleAsyncOptions` | NestJS wiring type for `forRootAsync()` |
| `AuthService` | All use-case methods |
| `AuthError` | Domain error class thrown by `AuthService` |
| `AuthErrorCode` | Typed error code constants |
| `AuthExceptionFilter` | NestJS filter — maps `AuthError` codes to HTTP responses |
| `JwtAuthGuard` | Protect routes; respects `@Public()` |
| `GoogleOAuthGuard` | Initiate / handle Google OAuth |
| `@CurrentUser()` | Extract `RequestUser` from request |
| `@Public()` | Opt out of global `JwtAuthGuard` |
| `JoseJwtSigner` | Default JWT adapter (jose) |
| `Argon2PasswordHasher` | Default password adapter (argon2id) |
| `CryptoTokenHasher` | Default token adapter (node:crypto) |
| `BearerTokenExtractor` | Default extractor — `Authorization: Bearer` header |
| `CookieTokenExtractor` | Extractor — named HTTP cookie |
| `QueryParamTokenExtractor` | Extractor — URL query parameter |
| `ConsoleLogger` | Default logger adapter (console.log / console.error, zero deps) |
| `IJwtSigner` | Port — implement to swap JWT library |
| `IPasswordHasher` | Port — implement to swap password hasher |
| `ITokenHasher` | Port — implement to swap token hasher |
| `ITokenExtractor` | Port — implement to swap token extraction |
| `ILogger` | Port — implement to swap logger |
| `IUserRepository` | Port — implement in your infra layer |
| `IRefreshTokenRepository` | Port — implement in your infra layer |
| `PORTS`, `AUTH_CAPABILITIES` | DI tokens for testing overrides |
| All other interfaces | Full type surface |

## Environment variables

| Variable | Required | Description |
|---|---|---|
| `JWT_PRIVATE_KEY` | Asymmetric only | PEM-encoded EC/RSA private key |
| `JWT_PUBLIC_KEY` | Asymmetric only | PEM-encoded EC/RSA public key |
| `GOOGLE_CLIENT_ID` | `google` capability | OAuth 2.0 client ID |
| `GOOGLE_CLIENT_SECRET` | `google` capability | OAuth 2.0 client secret |
| `GOOGLE_CALLBACK_URL` | `google` capability | OAuth 2.0 callback URL |
