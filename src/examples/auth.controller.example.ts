/**
 * @file auth.controller.example.ts
 *
 * Reference-only file showing how to wire `AuthService` in two contexts:
 *
 * 1. **NestJS controller** — the standard path when using `AuthModule`.
 * 2. **Framework-agnostic handler** — plain Node.js usage without NestJS,
 *    demonstrating that `AuthService` works in any runtime.
 *
 * Copy and adapt the section relevant to you. Do not import this file.
 *
 * This file is excluded from the production build (`tsconfig.build.json`)
 * and is never shipped in the `dist/` output.
 */

// ═══════════════════════════════════════════════════════════════════════════
// PART 1 — NestJS controller (Express or Fastify via @nestjs/platform-*)
// ═══════════════════════════════════════════════════════════════════════════
//
// Prerequisites in app.module.ts:
//
//   providers: [
//     // Maps AuthError codes to HTTP responses automatically.
//     // Works with both Express and Fastify — uses NestJS ArgumentsHost.
//     { provide: APP_GUARD,  useClass: JwtAuthGuard },
//     { provide: APP_FILTER, useClass: AuthExceptionFilter },
//   ]
//
// Without AuthExceptionFilter, AuthError propagates as an unhandled exception.
// You can also scope it per-controller with @UseFilters(AuthExceptionFilter).

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

// ── NestJS controller ─────────────────────────────────────────────────────

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  // ── Credentials ──────────────────────────────────────────────────────────

  @Public()
  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Public()
  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: LoginDto) {
    return this.authService.loginWithCredentials(dto);
  }

  // ── Google OAuth ──────────────────────────────────────────────────────────

  @Public()
  @Get('google')
  @UseGuards(GoogleOAuthGuard)
  googleLogin() {
    // Passport handles the redirect — no body needed.
  }

  @Public()
  @Get('google/callback')
  @UseGuards(GoogleOAuthGuard)
  googleCallback(@Req() req: AuthenticatedRequest) {
    return this.authService.handleGoogleCallback(req.user);
  }

  // ── Refresh tokens ────────────────────────────────────────────────────────

  @Public()
  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  refresh(@Body() dto: RefreshDto) {
    return this.authService.rotateRefreshToken(dto.refreshToken);
  }

  @Post('logout')
  @HttpCode(HttpStatus.NO_CONTENT)
  logout(@CurrentUser() user: RequestUser) {
    return this.authService.logout(user.userId);
  }

  // ── Protected ─────────────────────────────────────────────────────────────

  @Get('me')
  me(@CurrentUser() user: RequestUser) {
    return user;
  }

  // ── Password management ───────────────────────────────────────────────────

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

// ═══════════════════════════════════════════════════════════════════════════
// PART 2 — Framework-agnostic usage (no NestJS, no Passport)
// ═══════════════════════════════════════════════════════════════════════════
//
// AuthService is a plain class. Construct it directly with any framework.
// AuthError carries typed codes — map them to whatever your framework expects.
//
// Example below uses Fastify directly, but the same pattern works for:
//   plain Express, Hono, Elysia, Koa, queue workers, Lambda, CLI tools, etc.

/*
import Fastify from 'fastify';
import { AuthService } from '@odysseon/auth';
import { AuthError, AuthErrorCode } from '@odysseon/auth';
import { JoseJwtSigner } from '@odysseon/auth';
import { Argon2PasswordHasher } from '@odysseon/auth';
import { CryptoTokenHasher } from '@odysseon/auth';
import { ConsoleLogger } from '@odysseon/auth';

// ── Wire AuthService without NestJS ───────────────────────────────────────

const jwtConfig = {
  type: 'symmetric' as const,
  secret: process.env.JWT_SECRET!,
  accessToken: { expiresIn: '15m', algorithm: 'HS256' },
  refreshToken: { expiresIn: '7d' },
};

const authService = new AuthService(
  jwtConfig,
  new JoseJwtSigner(),
  new Argon2PasswordHasher(),
  new CryptoTokenHasher(),
  new ConsoleLogger(),
  new MyUserRepository(),        // your IUserRepository implementation
  new MyRefreshTokenRepository(), // your IRefreshTokenRepository implementation
);

// Call init() once at startup — validates config and imports JWT keys.
await authService.init();

// ── Map AuthError codes to HTTP responses ─────────────────────────────────

const AUTH_ERROR_STATUS: Record<string, number> = {
  [AuthErrorCode.INVALID_CREDENTIALS]:       401,
  [AuthErrorCode.EMAIL_ALREADY_EXISTS]:      409,
  [AuthErrorCode.OAUTH_ACCOUNT_NO_PASSWORD]: 400,
  [AuthErrorCode.PASSWORD_SAME_AS_OLD]:      400,
  [AuthErrorCode.USER_NOT_FOUND]:            404,
  [AuthErrorCode.OAUTH_USER_NOT_FOUND]:      401,
  [AuthErrorCode.ACCESS_TOKEN_INVALID]:      401,
  [AuthErrorCode.REFRESH_TOKEN_INVALID]:     401,
  [AuthErrorCode.REFRESH_TOKEN_EXPIRED]:     401,
  [AuthErrorCode.REFRESH_NOT_ENABLED]:       501,
};

function handleAuthError(err: unknown, reply: FastifyReply): boolean {
  if (err instanceof AuthError) {
    const status = AUTH_ERROR_STATUS[err.code] ?? 500;
    reply.status(status).send({ error: err.code, message: err.message });
    return true;
  }
  return false;
}

// ── Fastify routes ────────────────────────────────────────────────────────

const fastify = Fastify();

fastify.post('/auth/register', async (request, reply) => {
  try {
    const body = request.body as { email: string; password: string };
    const result = await authService.register(body);
    return reply.status(201).send(result);
  } catch (err) {
    if (!handleAuthError(err, reply)) throw err;
  }
});

fastify.post('/auth/login', async (request, reply) => {
  try {
    const body = request.body as { email: string; password: string };
    const result = await authService.loginWithCredentials(body);
    return reply.send(result);
  } catch (err) {
    if (!handleAuthError(err, reply)) throw err;
  }
});

fastify.post('/auth/refresh', async (request, reply) => {
  try {
    const body = request.body as { refreshToken: string };
    const result = await authService.rotateRefreshToken(body.refreshToken);
    return reply.send(result);
  } catch (err) {
    if (!handleAuthError(err, reply)) throw err;
  }
});

// Protect routes manually — verify the access token in a preHandler hook.
fastify.addHook('preHandler', async (request, reply) => {
  // Skip public routes.
  const publicPaths = ['/auth/register', '/auth/login', '/auth/refresh'];
  if (publicPaths.includes(request.url)) return;

  const token = request.headers.authorization?.slice(7); // strip "Bearer "
  if (!token) return reply.status(401).send({ error: 'Missing token' });

  try {
    (request as any).user = await authService.verifyAccessToken(token);
  } catch {
    return reply.status(401).send({ error: 'Invalid or expired token' });
  }
});

fastify.get('/auth/me', async (request) => {
  return (request as any).user;
});

await fastify.listen({ port: 3000 });
*/
