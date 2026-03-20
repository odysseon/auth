/**
 * Port: JWT extraction from an incoming HTTP request.
 *
 * `JwtStrategy` depends only on this interface — it never calls
 * `passport-jwt`'s `ExtractJwt` helpers directly. Swap the extraction
 * strategy by providing a different adapter class to
 * `AuthModule.forRootAsync({ tokenExtractor: MyExtractor })`.
 *
 * ### Contract
 * - Accept `request: unknown` so the port stays framework-agnostic at the
 *   interface level. Adapters narrow to `express.Request` internally.
 * - Return the raw token string when found, or `null` when absent.
 * - **Never throw.** A missing token is not an error at extraction time;
 *   Passport treats a `null` return as "no token" and will call the
 *   strategy's failure path.
 *
 * ### Matching `passport-jwt`
 * `passport-jwt` calls the extractor as `fromRequest(req): string | null`.
 * `ITokenExtractor.extract` has the identical signature so it can be
 * passed directly:
 *
 * ```ts
 * super({ jwtFromRequest: (req) => this.tokenExtractor.extract(req), ... })
 * ```
 */
export interface ITokenExtractor {
  /**
   * Extract a JWT from the request.
   *
   * @param request  The raw incoming request object. Adapters cast this to
   *                 the framework type they expect (e.g. `express.Request`).
   * @returns        The compact JWT string, or `null` if not found.
   */
  extract(request: unknown): string | null;
}
