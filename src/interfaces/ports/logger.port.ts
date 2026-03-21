/**
 * Port: structured logging.
 *
 * `AuthService` depends only on this interface — it never imports
 * `@nestjs/common`'s `Logger` or any other logging library directly.
 *
 * The default adapter (`ConsoleLogger`) writes to stdout via `console.log`.
 * Swap it to get NestJS structured logging, Pino, Winston, or any sink:
 *
 * ```ts
 * // nestjs-logger.adapter.ts
 * import { Logger } from '@nestjs/common';
 *
 * @Injectable()
 * export class NestJsLogger implements ILogger {
 *   private readonly logger = new Logger('AuthService');
 *   log(message: string)                    { this.logger.log(message); }
 *   error(message: string, ctx?: unknown)   { this.logger.error(message, ctx); }
 * }
 *
 * // AuthModule.forRootAsync({ logger: NestJsLogger, ... })
 * ```
 */
export interface ILogger {
  log(message: string): void;
  error(message: string, context?: unknown): void;
}
