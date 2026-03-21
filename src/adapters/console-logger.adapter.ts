import type { ILogger } from '../interfaces/ports/logger.port';

/**
 * Default `ILogger` adapter — writes to stdout/stderr via `console`.
 * No external dependencies beyond Node.js itself.
 *
 * Swap this by implementing `ILogger` and passing
 * `logger: YourClass` to `AuthModule.forRootAsync()`.
 */
export class ConsoleLogger implements ILogger {
  log(message: string): void {
    console.log(`[AuthService] ${message}`);
  }

  error(message: string, context?: unknown): void {
    console.error(`[AuthService] ${message}`, context ?? '');
  }
}
