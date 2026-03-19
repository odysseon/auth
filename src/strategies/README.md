# src/strategies/

Passport strategies — the HTTP-boundary adapters that extract and validate
credentials from incoming requests.

## `jwt.strategy.ts` — `JwtStrategy`

Validates `Authorization: Bearer <token>` on every protected route.

Steps:
1. Extracts the token from the Bearer header.
2. Verifies signature using the key from `JwtConfig` (symmetric or asymmetric).
3. Checks expiry, issuer, and audience claims (if configured).
4. Rejects tokens where `payload.type !== 'access'` — prevents a refresh
   token from being presented as an access token.
5. Resolves to `{ userId: payload.sub }` which Passport attaches to `req.user`.

No database call is made per request — the JWT is self-contained.

## `google.strategy.ts` — `GoogleStrategy`

Handles the Google OAuth 2.0 round-trip.

Steps:
1. Validates that Google returned a verified email address.
2. Looks up the user by Google subject ID (`profile.id`).
3. If not found, checks for an existing account with the same email and
   links the Google ID to it (account merging).
4. If still not found, creates a new user record.
5. Resolves to `{ userId }` which `AuthService.handleGoogleCallback()` then
   uses to issue a token pair.

### Why user creation lives here, not in `AuthService`

Passport strategies are the entry point for OAuth flows. The strategy
already has access to the full Google profile and must resolve a `userId`
synchronously within Passport's `validate()` lifecycle. Pushing the
find-or-create logic into `AuthService` would require an extra round-trip
or a more complex interface. The strategy acts as the "Google adapter" at
the Passport boundary; `AuthService` stays focused on token issuance.

## Adding a new strategy

1. Create `src/strategies/my-provider.strategy.ts`.
2. Add a DI token to `src/constants/` if the strategy needs its own config.
3. Register the strategy as a provider in `AuthModule.forRootAsync()`.
4. Add a corresponding guard in `src/guards/`.
