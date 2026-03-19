import { SetMetadata } from '@nestjs/common';

export const IS_PUBLIC_KEY = 'isPublic' as const;

/**
 * Mark a route handler or controller as publicly accessible.
 *
 * When `JwtAuthGuard` is applied globally, decorate any endpoint that must
 * remain unauthenticated (e.g. `/auth/login`, `/auth/google`) with this.
 *
 * ```ts
 * @Public()
 * @Post('login')
 * login(@Body() dto: LoginDto) { ... }
 * ```
 */
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);
