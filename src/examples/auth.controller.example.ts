/**
 * @file auth.controller.example.ts
 *
 * Reference-only controller showing how to wire every `AuthService` method
 * into a NestJS controller. Copy and adapt — do not import this file.
 *
 * This file is excluded from the production build (`tsconfig.build.json`)
 * and is never shipped in the `dist/` output.
 *
 * ### Assumptions
 * - `JwtAuthGuard` is registered globally via `APP_GUARD` (recommended).
 *   Routes that must be publicly accessible are decorated with `@Public()`.
 * - `RegisterDto` / `LoginDto` / `ChangePasswordDto` are your own validation
 *   DTOs (e.g. class-validator). They are not provided by this module.
 */

import {
  Controller,
  Get,
  Post,
  Body,
  Req,
  UseGuards,
  HttpCode,
  HttpStatus,
} from '@nestjs/common';
import { AuthService } from '../core/auth.service';
import { GoogleOAuthGuard } from '../guards/google-oauth.guard';
import { CurrentUser } from '../decorators/current-user.decorator';
import { Public } from '../decorators/public.decorator';
import type { AuthenticatedRequest } from '../interfaces/user-model/authenticated-request.interface';
import type { RequestUser } from '../interfaces/user-model/request-user.interface';

// ── Minimal inline DTOs (replace with your own class-validator DTOs) ──────

interface RegisterDto {
  email: string;
  password: string;
}

interface LoginDto {
  email: string;
  password: string;
}

interface RefreshDto {
  refreshToken: string;
}

interface ChangePasswordDto {
  currentPassword: string;
  newPassword: string;
}

// ── Controller ────────────────────────────────────────────────────────────

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ── Credentials ──────────────────────────────────────────────────────────

  /**
   * POST /auth/register
   * Create a new user and return a token pair.
   */
  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  /**
   * POST /auth/login
   * Verify email + password and return a token pair.
   */
  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: LoginDto) {
    return this.authService.loginWithCredentials(dto);
  }

  // ── Google OAuth ──────────────────────────────────────────────────────────

  /**
   * GET /auth/google
   * Redirects the browser to Google's OAuth consent screen.
   */
  @Public()
  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  googleLogin() {
    // Passport handles the redirect — no body needed.
  }

  /**
   * GET /auth/google/callback
   * Google redirects here after the user grants consent.
   * Passport calls GoogleStrategy.validate(), which resolves req.user,
   * then this handler issues a token pair.
   */
  @Public()
  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  googleCallback(@Req() req: AuthenticatedRequest) {
    return this.authService.handleGoogleCallback(req.user);
  }

  // ── Refresh tokens ────────────────────────────────────────────────────────

  /**
   * POST /auth/refresh
   * Atomically consume the supplied refresh token and issue a fresh pair.
   * The old token is invalidated immediately — replay is rejected.
   */
  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(@Body() dto: RefreshDto) {
    return this.authService.rotateRefreshToken(dto.refreshToken);
  }

  /**
   * POST /auth/logout
   * Revoke every refresh token for the authenticated user (all devices).
   * Access tokens remain valid until their `exp` claim — keep TTLs short.
   */
  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  logout(@CurrentUser() user: RequestUser) {
    return this.authService.logout(user.userId);
  }

  // ── Protected ─────────────────────────────────────────────────────────────

  /**
   * GET /auth/me
   * Return the authenticated user's identity.
   * Protected by the global JwtAuthGuard — no @UseGuards needed.
   */
  @Get('me')
  me(@CurrentUser() user: RequestUser) {
    return user;
  }

  // ── Password management ───────────────────────────────────────────────────

  /**
   * POST /auth/password/change
   * Change the authenticated user's password.
   * Requires the current password for verification.
   */
  @Post('password/change')
  @HttpCode(HttpStatus.OK)
  changePassword(
    @CurrentUser() user: RequestUser,
    @Body() dto: ChangePasswordDto,
  ) {
    return this.authService.changePassword({
      userId: user.userId,
      currentPassword: dto.currentPassword,
      newPassword: dto.newPassword,
    });
  }
}
