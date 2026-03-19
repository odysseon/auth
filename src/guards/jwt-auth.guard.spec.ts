import { ExecutionContext } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtAuthGuard } from './jwt-auth.guard';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

function buildContext(): ExecutionContext {
  return {
    getHandler: jest.fn().mockReturnValue({}),
    getClass: jest.fn().mockReturnValue({}),
    switchToHttp: jest.fn(),
  } as unknown as ExecutionContext;
}

describe('JwtAuthGuard', () => {
  let reflector: jest.Mocked<Reflector>;
  let guard: JwtAuthGuard;

  beforeEach(() => {
    reflector = {
      getAllAndOverride: jest.fn(),
    } as unknown as jest.Mocked<Reflector>;

    guard = new JwtAuthGuard(reflector);
  });

  it('returns true immediately for routes marked @Public()', () => {
    reflector.getAllAndOverride.mockReturnValue(true);
    const ctx = buildContext();

    const result = guard.canActivate(ctx);

    expect(result).toBe(true);
    expect(reflector.getAllAndOverride).toHaveBeenCalledWith(IS_PUBLIC_KEY, [
      expect.anything(),
      expect.anything(),
    ]);
  });

  it('delegates to the parent AuthGuard when route is not @Public()', () => {
    reflector.getAllAndOverride.mockReturnValue(false);
    const ctx = buildContext();

    // Spy on the parent canActivate — we don't want to run the real Passport
    // pipeline, just confirm delegation happens.
    const parentActivate = jest
      .spyOn(Object.getPrototypeOf(JwtAuthGuard.prototype), 'canActivate')
      .mockReturnValue(true);

    guard.canActivate(ctx);

    expect(parentActivate).toHaveBeenCalledWith(ctx);

    parentActivate.mockRestore();
  });

  it('delegates when @Public() metadata is absent (undefined)', () => {
    reflector.getAllAndOverride.mockReturnValue(undefined);
    const ctx = buildContext();

    const parentActivate = jest
      .spyOn(Object.getPrototypeOf(JwtAuthGuard.prototype), 'canActivate')
      .mockReturnValue(true);

    guard.canActivate(ctx);

    expect(parentActivate).toHaveBeenCalled();
    parentActivate.mockRestore();
  });
});
