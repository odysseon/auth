# src/strategies/

Passport strategies — the HTTP-boundary adapters that extract and validate
credentials from incoming requests.

## `jwt.strategy.ts` — `JwtStrategy`

Validates JWTs on every protected route.

Steps:
1. Delegates token extraction to the injected `ITokenExtractor`
   (`PORTS.TOKEN_EXTRACTOR`). The default is `BearerTokenExtractor`
   (`Authorization: Bearer <token>`). Swap it via
   `AuthModule.forRootAsync({ tokenExtractor: ... })` to read from a cookie,
   a query parameter, or any custom source.
2. Verifies the token signature using the key from `JwtConfig`
   (symmetric or asymmetric).
3. Checks expiry, issuer, and audience claims (if configured).
4. Rejects tokens where `payload.type !== 'access'` — prevents a refresh
   token from being presented as an access token.
5. Resolves to `{ userId: payload.sub }` which Passport attaches to `req.user`.

No database call is made per request — the JWT is self-contained.

## `google.strategy.ts` — `GoogleStrategy`

Handles the Google OAuth 2.0 round-trip.

Steps:
1. Confirms that Google returned an email address on the profile (required
   for account lookup — not an in-module verification step).
2. Looks up the user by Google subject ID (`profile.id`).
3. If not found, checks for an existing account with the same email and
   links the Google ID to it (account merging).
4. If still not found, creates a new user record.
5. Resolves to `{ userId }` which `AuthService.handleGoogleCallback()` then
   uses to issue a token pair.

### Why user creation lives here, not in `AuthService`

Passport strategies are the entry point for OAuth flows. The strategy
already has access to the full Google profile and must resolve a `userId`
within Passport's `validate()` lifecycle. Pushing the find-or-create logic
into `AuthService` would require a more complex interface. The strategy
acts as the "Google adapter" at the Passport boundary; `AuthService` stays
focused on token issuance.

### Error handling in `validate()`

Two categories of failure are distinguished:

- **Expected auth failures** (no email returned, user cannot be resolved):
  `done(new UnauthorizedException(...))`. Passport recognises `HttpException`
  instances and routes them through the *fail* path, producing a 401. The
  client receives the correct status without the error surfacing as a crash.

- **Unexpected exceptions** (repository errors, network failures):
  `done(err)` in the `catch` block. Passport routes these through the *error*
  path, producing a 500 and preserving the original stack trace for debugging.

## Adding a new strategy

1. Create `src/strategies/my-provider.strategy.ts`.
2. Add a DI token to `src/constants/` if the strategy needs its own config.
3. Register the strategy as a provider in `AuthModule.forRootAsync()`.
4. Add a corresponding guard in `src/guards/`.
