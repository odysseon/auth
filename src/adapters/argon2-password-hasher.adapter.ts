import { Injectable } from '@nestjs/common';
import type { IPasswordHasher } from '../interfaces/ports/password-hasher.port';

// Lazy-load so projects that only use Google OAuth never need argon2 installed.
let _argon2: typeof import('argon2') | null = null;

async function getArgon2(): Promise<typeof import('argon2')> {
  if (_argon2) return _argon2;
  try {
    _argon2 = await import('argon2');
    return _argon2;
  } catch {
    throw new Error(
      '[@odysseon/auth] Argon2PasswordHasher requires the `argon2` package.\n' +
        'Install it:  pnpm add argon2\n' +
        'Or supply a custom passwordHasher adapter that does not need argon2.',
    );
  }
}

/**
 * Default `IPasswordHasher` adapter — uses **argon2id** (OWASP recommended).
 *
 * ### Swapping this adapter
 * Pass `passwordHasher: YourHasherClass` to `AuthModule.forRootAsync()` and
 * implement `IPasswordHasher`.  No other files need to change.
 *
 * ```ts
 * // bcrypt-password-hasher.adapter.ts
 * import * as bcrypt from 'bcrypt';
 *
 * @Injectable()
 * export class BcryptPasswordHasher implements IPasswordHasher {
 *   async hash(password: string)                    { return bcrypt.hash(password, 12); }
 *   async verify(password: string, hash: string)    { return bcrypt.compare(password, hash); }
 * }
 * ```
 */
@Injectable()
export class Argon2PasswordHasher implements IPasswordHasher {
  async hash(password: string): Promise<string> {
    const argon2 = await getArgon2();
    return argon2.hash(password);
  }

  async verify(password: string, hash: string): Promise<boolean> {
    const argon2 = await getArgon2();
    try {
      return await argon2.verify(hash, password);
    } catch {
      return false;
    }
  }
}
