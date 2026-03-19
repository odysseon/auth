# src/decorators/

Parameter and metadata decorators exported for use in consumer controllers.

## `@CurrentUser(key?)`

Extracts `RequestUser` (or a single field) from `request.user`.

Requires the route to be protected by `JwtAuthGuard` — the guard populates
`request.user` before the decorator runs.

```ts
// Whole object
@Get('me')
@UseGuards(JwtAuthGuard)
me(@CurrentUser() user: RequestUser) {
  return user; // { userId: 'abc-123' }
}

// Single field
@Delete('account')
@UseGuards(JwtAuthGuard)
deleteAccount(@CurrentUser('userId') id: string) { ... }
```

## `@Public()`

Marks a route or controller as publicly accessible, opting it out of a
globally applied `JwtAuthGuard`.

```ts
@Public()
@Post('register')
register(@Body() dto: RegisterDto) { ... }
```

### How it works

`@Public()` calls `SetMetadata(IS_PUBLIC_KEY, true)`. `JwtAuthGuard` reads
this metadata via `Reflector` and skips JWT validation when the flag is set.

Re-export `IS_PUBLIC_KEY` if you build your own guard and need to read the
same metadata key.
