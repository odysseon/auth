import { Injectable, ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { AuthGuard } from '@nestjs/passport';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

/**
 * Guard that enforces JWT authentication on every route by default.
 *
 * Decorate a route or controller with `@Public()` to opt out.
 *
 * ### Global usage (recommended)
 * ```ts
 * // app.module.ts
 * providers: [
 *   { provide: APP_GUARD, useClass: JwtAuthGuard },
 * ]
 * ```
 *
 * ### Per-route usage
 * ```ts
 * @UseGuards(JwtAuthGuard)
 * @Get('me')
 * me(@CurrentUser() user: RequestUser) { ... }
 * ```
 */
@Injectable()
export class JwtAuthGuard extends AuthGuard('jwt') {
  constructor(private readonly reflector: Reflector) {
    super();
  }

  canActivate(ctx: ExecutionContext) {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      ctx.getHandler(),
      ctx.getClass(),
    ]);
    if (isPublic) return true;
    return super.canActivate(ctx);
  }
}
