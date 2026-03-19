# src/adapters/

Default implementations of the three internal ports. Every adapter in this
directory is **swappable** — pass a replacement class to
`AuthModule.forRootAsync()` and the rest of the module is completely unaffected.

## Adapters

### `JoseJwtSigner` → `IJwtSigner`

Wraps the **jose** library for JWT signing and verification.

**Why jose?**
- Uses the Web Crypto API — hardware-acceleratable, FIPS-certifiable.
- Works in Node, Deno, Bun, and edge runtimes unchanged.
- Zero sub-dependencies.

**To swap:** Implement `IJwtSigner` and pass `jwtSigner: YourClass`.

```ts
// jsonwebtoken-signer.adapter.ts
@Injectable()
export class JsonwebtokenSigner implements IJwtSigner {
  async init(config: JwtConfig) { /* import key */ }
  async sign(payload, expiresIn) { return jwt.sign(payload, this.key, { expiresIn }); }
  async verify(token) { return jwt.verify(token, this.key) as JwtPayload; }
}

// AuthModule.forRootAsync({ jwtSigner: JsonwebtokenSigner, ... })
```

---

### `Argon2PasswordHasher` → `IPasswordHasher`

Wraps **argon2id** for password hashing.

argon2 is declared as an **optional** peer dependency — it is lazy-loaded
at runtime. Projects that use only Google OAuth never need it installed.

**To swap:** Implement `IPasswordHasher` and pass `passwordHasher: YourClass`.

```ts
// bcrypt-password-hasher.adapter.ts
@Injectable()
export class BcryptPasswordHasher implements IPasswordHasher {
  async hash(password: string)                 { return bcrypt.hash(password, 12); }
  async verify(password: string, hash: string) { return bcrypt.compare(password, hash); }
}

// AuthModule.forRootAsync({ passwordHasher: BcryptPasswordHasher, ... })
```

---

### `CryptoTokenHasher` → `ITokenHasher`

Wraps Node's built-in **`crypto`** module. No extra dependencies.

SHA-256 is used for hashing refresh tokens because the tokens being hashed
are already high-entropy random byte strings (256-bit default). A slow
password hashing function is unnecessary here and would add latency.

**To swap:** Implement `ITokenHasher` and pass `tokenHasher: YourClass`.

```ts
// kms-token-hasher.adapter.ts
@Injectable()
export class KmsTokenHasher implements ITokenHasher {
  hash(token: string)    { return kmsClient.hash(token); }
  generate(bytes = 32)   { return kmsClient.random(bytes); }
}

// AuthModule.forRootAsync({ tokenHasher: KmsTokenHasher, ... })
```

## Dependency direction

```
interfaces/ports/  (contracts — no deps)
      ↑
adapters/          (default implementations — depend on external libs)
      ↑
core/              (AuthModule wires ports → adapters via DI tokens)
```

The core never imports from adapters directly — it only knows about ports.
