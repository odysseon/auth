import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

/**
 * Triggers the Google OAuth redirect on the initiation route and processes
 * the callback on the return route.
 *
 * ```ts
 * @Get('google')
 * @UseGuards(GoogleOAuthGuard)
 * @Public()
 * googleLogin() {} // guard handles redirect — no body needed
 *
 * @Get('google/callback')
 * @UseGuards(GoogleOAuthGuard)
 * @Public()
 * async googleCallback(@Req() req: AuthenticatedRequest) {
 *   return this.authService.handleGoogleCallback(req.user);
 * }
 * ```
 */
@Injectable()
export class GoogleOAuthGuard extends AuthGuard('google') {}
