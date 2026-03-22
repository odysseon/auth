import { ConsoleLogger } from './console-logger.adapter';

describe('ConsoleLogger', () => {
  let logger: ConsoleLogger;
  let logSpy: jest.SpyInstance;
  let errorSpy: jest.SpyInstance;

  beforeEach(() => {
    logger = new ConsoleLogger();
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    logSpy.mockRestore();
    errorSpy.mockRestore();
  });

  describe('log', () => {
    it('writes to console.log with the AuthService prefix', () => {
      logger.log('user registered');
      expect(logSpy).toHaveBeenCalledWith('[AuthService] user registered');
    });
  });

  describe('error', () => {
    it('writes to console.error with the AuthService prefix', () => {
      logger.error('something failed');
      expect(errorSpy).toHaveBeenCalledWith(
        '[AuthService] something failed',
        '',
      );
    });

    it('includes context when provided', () => {
      const ctx = { detail: 'stack trace' };
      logger.error('something failed', ctx);
      expect(errorSpy).toHaveBeenCalledWith(
        '[AuthService] something failed',
        ctx,
      );
    });
  });
});
