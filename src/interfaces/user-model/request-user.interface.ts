/**
 * Minimal identity payload stored on the HTTP request after JWT validation.
 * Intentionally tiny — no email, no roles.  Controllers receive this via
 * the @CurrentUser() decorator.
 */
export interface RequestUser {
  /** The authenticated user's stable identifier. */
  userId: string;
}
