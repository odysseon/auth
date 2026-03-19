import type { Request } from 'express';
import type { RequestUser } from './request-user.interface';

/** Express Request extended with a validated user identity. */
export interface AuthenticatedRequest extends Request {
  user: RequestUser;
}
