import { Injectable } from '@nestjs/common';
import { randomBytes, createHash } from 'crypto';
import type { ITokenHasher } from '../interfaces/ports/token-hasher.port';

/**
 * Default `ITokenHasher` adapter — uses Node's built-in `crypto` module.
 * No extra dependencies required.
 *
 * SHA-256 is appropriate here because the tokens being hashed are already
 * high-entropy random byte strings (256-bit default). A slow password
 * hashing function would be wasteful and is unnecessary.
 *
 * ### Swapping this adapter
 * Pass `tokenHasher: YourHasherClass` to `AuthModule.forRootAsync()` and
 * implement `ITokenHasher`.  Useful if you want to delegate token generation
 * to a KMS or HSM.
 *
 * ```ts
 * @Injectable()
 * export class KmsTokenHasher implements ITokenHasher {
 *   hash(token: string)       { return kmsClient.hash(token); }
 *   generate(bytes = 32)      { return kmsClient.random(bytes); }
 * }
 * ```
 */
@Injectable()
export class CryptoTokenHasher implements ITokenHasher {
  hash(token: string): string {
    return createHash('sha256').update(token).digest('hex');
  }

  generate(bytes = 32): string {
    return randomBytes(bytes).toString('hex');
  }
}
