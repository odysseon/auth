import {
  Catch,
  ExceptionFilter,
  ArgumentsHost,
  HttpStatus,
} from '@nestjs/common';
import { AuthError, AuthErrorCode } from '../errors/auth-error';

/**
 * NestJS exception filter that maps `AuthError` domain errors to HTTP
 * responses. Register it globally or per-controller in the consuming app:
 *
 * ```ts
 * // Global — app.module.ts
 * providers: [{ provide: APP_FILTER, useClass: AuthExceptionFilter }]
 *
 * // Per-controller
 * @UseFilters(AuthExceptionFilter)
 * @Controller('auth')
 * export class AuthController { ... }
 * ```
 *
 * Works with both Express and Fastify — it accesses the response through
 * NestJS's `ArgumentsHost` abstraction, not through a framework-specific API.
 */
@Catch(AuthError)
export class AuthExceptionFilter implements ExceptionFilter {
  private static readonly STATUS_MAP: Record<AuthErrorCode, HttpStatus> = {
    [AuthErrorCode.INVALID_CREDENTIALS]: HttpStatus.UNAUTHORIZED,
    [AuthErrorCode.EMAIL_ALREADY_EXISTS]: HttpStatus.CONFLICT,
    [AuthErrorCode.OAUTH_ACCOUNT_NO_PASSWORD]: HttpStatus.BAD_REQUEST,
    [AuthErrorCode.PASSWORD_SAME_AS_OLD]: HttpStatus.BAD_REQUEST,
    [AuthErrorCode.USER_NOT_FOUND]: HttpStatus.NOT_FOUND,
    [AuthErrorCode.OAUTH_USER_NOT_FOUND]: HttpStatus.UNAUTHORIZED,
    [AuthErrorCode.ACCESS_TOKEN_INVALID]: HttpStatus.UNAUTHORIZED,
    [AuthErrorCode.REFRESH_TOKEN_INVALID]: HttpStatus.UNAUTHORIZED,
    [AuthErrorCode.REFRESH_TOKEN_EXPIRED]: HttpStatus.UNAUTHORIZED,
    [AuthErrorCode.REFRESH_NOT_ENABLED]: HttpStatus.NOT_IMPLEMENTED,
  };

  catch(error: AuthError, host: ArgumentsHost): void {
    const status =
      AuthExceptionFilter.STATUS_MAP[error.code] ??
      HttpStatus.INTERNAL_SERVER_ERROR;

    const body = {
      statusCode: status,
      error: error.code,
      message: error.message,
    };

    const http = host.switchToHttp();

    // NestJS's HttpArgumentsHost works identically for Express and Fastify —
    // getResponse() returns the platform's response object and the `.status()`
    // / `.send()` / `.json()` methods are normalised by the NestJS adapter.
    const response = http.getResponse<{
      status(code: number): { json(body: unknown): void };
    }>();
    response.status(status).json(body);
  }
}
