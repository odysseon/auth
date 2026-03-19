/** Input required for email/password login. */
export interface LoginInput {
  email: string;
  password: string;
}

/** Input required for new user registration. */
export interface RegistrationInput {
  email: string;
  password: string;
}

/** Input for changing a password when the current one is known. */
export interface PasswordChangeInput {
  userId: string;
  currentPassword: string;
  newPassword: string;
}

/** Input for an admin/forgot-password reset (no current password needed). */
export interface PasswordSetInput {
  userId: string;
  newPassword: string;
}
