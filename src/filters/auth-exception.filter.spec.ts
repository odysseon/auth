import { ArgumentsHost, HttpStatus } from '@nestjs/common';
import { AuthExceptionFilter } from './auth-exception.filter';
import { AuthError, AuthErrorCode } from '../errors/auth-error';

function buildHost(jsonMock = jest.fn()): ArgumentsHost {
  const statusMock = jest.fn().mockReturnValue({ json: jsonMock });
  const responseMock = { status: statusMock };
  const httpMock = { getResponse: jest.fn().mockReturnValue(responseMock) };
  return {
    switchToHttp: jest.fn().mockReturnValue(httpMock),
  } as unknown as ArgumentsHost;
}

describe('AuthExceptionFilter', () => {
  let filter: AuthExceptionFilter;

  beforeEach(() => {
    filter = new AuthExceptionFilter();
  });

  describe('known error codes → correct HTTP status', () => {
    const cases: [AuthErrorCode, HttpStatus][] = [
      [AuthErrorCode.INVALID_CREDENTIALS,       HttpStatus.UNAUTHORIZED],
      [AuthErrorCode.EMAIL_ALREADY_EXISTS,       HttpStatus.CONFLICT],
      [AuthErrorCode.OAUTH_ACCOUNT_NO_PASSWORD,  HttpStatus.BAD_REQUEST],
      [AuthErrorCode.PASSWORD_SAME_AS_OLD,       HttpStatus.BAD_REQUEST],
      [AuthErrorCode.USER_NOT_FOUND,             HttpStatus.NOT_FOUND],
      [AuthErrorCode.OAUTH_USER_NOT_FOUND,       HttpStatus.UNAUTHORIZED],
      [AuthErrorCode.ACCESS_TOKEN_INVALID,       HttpStatus.UNAUTHORIZED],
      [AuthErrorCode.REFRESH_TOKEN_INVALID,      HttpStatus.UNAUTHORIZED],
      [AuthErrorCode.REFRESH_TOKEN_EXPIRED,      HttpStatus.UNAUTHORIZED],
      [AuthErrorCode.REFRESH_NOT_ENABLED,        HttpStatus.NOT_IMPLEMENTED],
    ];

    it.each(cases)('%s → %s', (code, expectedStatus) => {
      const json = jest.fn();
      const host = buildHost(json);
      const error = new AuthError(code, 'test message');

      filter.catch(error, host);

      const { status } = (
        host.switchToHttp().getResponse<{ status: jest.Mock }>()
      );
      expect(status).toHaveBeenCalledWith(expectedStatus);
      expect(json).toHaveBeenCalledWith({
        statusCode: expectedStatus,
        error: code,
        message: 'test message',
      });
    });
  });

  describe('response body shape', () => {
    it('includes statusCode, error code, and message', () => {
      const json = jest.fn();
      const host = buildHost(json);
      const error = new AuthError(
        AuthErrorCode.INVALID_CREDENTIALS,
        'Invalid credentials',
      );

      filter.catch(error, host);

      expect(json).toHaveBeenCalledWith({
        statusCode: HttpStatus.UNAUTHORIZED,
        error: AuthErrorCode.INVALID_CREDENTIALS,
        message: 'Invalid credentials',
      });
    });

    it('falls back to 500 when the error code has no mapping', () => {
      const json = jest.fn();
      const host = buildHost(json);
      // Force an unknown code that is not in STATUS_MAP
      const error = new AuthError(
        'UNKNOWN_CODE' as AuthErrorCode,
        'unexpected failure',
      );

      filter.catch(error, host);

      const { status } = host
        .switchToHttp()
        .getResponse<{ status: jest.Mock }>();
      expect(status).toHaveBeenCalledWith(HttpStatus.INTERNAL_SERVER_ERROR);
    });
  });
});
