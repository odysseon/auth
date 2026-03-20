import { Injectable, Inject, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy, Profile, VerifyCallback } from 'passport-google-oauth20';
import { AUTH_CAPABILITIES, PORTS } from '../constants';
import type {
  GoogleOAuthConfig,
  IGoogleUserRepository,
  AuthUser,
  RequestUser,
} from '../interfaces';

/**
 * Passport strategy for Google OAuth 2.0.
 *
 * Responsibilities (identity only):
 * - Confirm that Google returned an email address on the profile (a
 *   prerequisite for account lookup — not an in-module verification step).
 * - Find the user by Google subject ID; if absent, look up by email and link
 *   the Google ID; if still absent, create a new user record.
 * - Attach `{ userId }` to `request.user` — controllers receive this via
 *   `@CurrentUser()` and hand it to `AuthService.handleGoogleCallback()`.
 *
 * User creation/linking is intentionally kept in this strategy so that
 * `AuthService` stays focused on token issuance. The strategy acts as the
 * "find-or-create" adapter at the Passport boundary.
 *
 * Note: email-verification semantics are out of scope for this module and
 * are left entirely to the consuming application.
 */
@Injectable()
export class GoogleStrategy extends PassportStrategy(Strategy, 'google') {
  constructor(
    @Inject(AUTH_CAPABILITIES.GOOGLE)
    config: GoogleOAuthConfig,
    @Inject(PORTS.USER_REPOSITORY)
    private readonly userRepo: IGoogleUserRepository<Partial<AuthUser>>,
  ) {
    if (!config) {
      throw new Error(
        '[@odysseon/auth] GoogleStrategy instantiated but no Google config ' +
          "was provided. Add 'google' to enabledCapabilities and supply google config.",
      );
    }
    super({
      clientID: config.clientID,
      clientSecret: config.clientSecret,
      callbackURL: config.callbackURL,
      scope: config.scope ?? ['email', 'profile'],
    });
  }

  async validate(
    _accessToken: string,
    _refreshToken: string,
    profile: Profile,
    done: VerifyCallback,
  ): Promise<void> {
    try {
      const email = profile.emails?.[0]?.value;
      if (!email) {
        return done(
          new UnauthorizedException(
            'Google did not return an email address. Ensure your Google ' +
              'account has a verified email and the email scope is granted.',
          ),
        );
      }

      // 1. Fast path — user already has this Google ID linked.
      let user = await this.userRepo.findByGoogleId(profile.id);

      if (!user) {
        // 2. Check if an account with this email already exists (e.g. signed
        //    up via credentials earlier) — link rather than duplicate.
        user = await this.userRepo.findByEmail(email);
        if (user && user.id) {
          user = await this.userRepo.update(user.id, {
            googleId: profile.id,
          } as Partial<AuthUser>);
        } else {
          // 3. Brand new user — provision an account.
          user = await this.userRepo.create({
            email,
            googleId: profile.id,
          } as Partial<AuthUser>);
        }
      }

      if (!user?.id) {
        return done(
          new UnauthorizedException(
            'Failed to resolve user from Google profile',
          ),
        );
      }

      const requestUser: RequestUser = { userId: user.id };
      done(null, requestUser);
    } catch (err) {
      done(err as Error);
    }
  }
}
