import type { AuthUser } from './user.interface';

/**
 * Port: user persistence.
 *
 * Implement this interface in your infrastructure layer and pass the class to
 * `AuthModule.forRootAsync({ userRepository: MyUserRepository })`.
 *
 * The module will inject it wherever it needs to read or write users.
 */
export interface IUserRepository<
  User extends Partial<AuthUser> = Partial<AuthUser>,
> {
  findById(id: string): Promise<User | null>;
  findByEmail(email: string): Promise<User | null>;
  create(data: Partial<User>): Promise<User>;
  update(id: string, data: Partial<User>): Promise<User>;
}

/**
 * Extended port required when the `google` capability is enabled.
 * Your repository must additionally support lookup by Google subject ID.
 */
export interface IGoogleUserRepository<
  User extends Partial<AuthUser> = Partial<AuthUser>,
> extends IUserRepository<User> {
  findByGoogleId(googleId: string): Promise<User | null>;
}
