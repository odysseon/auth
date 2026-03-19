import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import type { RequestUser } from '../interfaces/user-model';

/**
 * Extracts the authenticated user identity from the request object.
 *
 * Only valid on routes protected by `JwtAuthGuard`.
 *
 * ```ts
 * @Get('me')
 * @UseGuards(JwtAuthGuard)
 * me(@CurrentUser() user: RequestUser) {
 *   return user; // { userId: '...' }
 * }
 * ```
 *
 * Pass a key to extract a single field:
 * ```ts
 * me(@CurrentUser('userId') id: string) { ... }
 * ```
 */
export const CurrentUser = createParamDecorator(
  (key: keyof RequestUser | undefined, ctx: ExecutionContext) => {
    const user = ctx.switchToHttp().getRequest().user as RequestUser;
    return key ? user?.[key] : user;
  },
);
