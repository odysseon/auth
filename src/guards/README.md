# src/guards/

NestJS guards that activate Passport strategies on incoming requests.

## `JwtAuthGuard`

Applies `JwtStrategy` to validate the Bearer token.

Supports `@Public()` — when the decorator is present on a route handler or
controller, the guard short-circuits and allows the request through without
checking for a token. This makes it safe to apply the guard globally.

### Global application (recommended)

```ts
// app.module.ts
providers: [
  { provide: APP_GUARD, useClass: JwtAuthGuard },
]
```

Then mark open endpoints:

```ts
@Public()
@Post('login')
login() { ... }
```

### Per-route application

```ts
@UseGuards(JwtAuthGuard)
@Get('me')
me(@CurrentUser() user: RequestUser) { ... }
```

## `GoogleOAuthGuard`

Thin wrapper around `AuthGuard('google')`. Triggers:

- On the **initiation route** (`GET /auth/google`): redirects to Google.
- On the **callback route** (`GET /auth/google/callback`): exchanges the
  code for tokens and calls `GoogleStrategy.validate()`.

Always combine with `@Public()` so `JwtAuthGuard` (if applied globally)
does not intercept these unauthenticated routes.
