import type { AccessTokenUser } from "./types.js";

export interface TokenCookieOptions {
  /** Default `Strict`. Use `Lax` only if users must arrive logged in from links on other sites. */
  sameSite?: "Strict" | "Lax";
  /** Default `/`. Scope a refresh token cookie to your refresh route, e.g. `/api/auth/refresh`. */
  path?: string;
  /** Lifetime in seconds. */
  maxAge: number;
  domain?: string;
  /** Default true. Only disable for plain-http localhost development. */
  secure?: boolean;
}

const COOKIE_NAME = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/;
const COOKIE_PATH = /^\/[\x21-\x3a\x3c-\x7e]*$/;
const COOKIE_DOMAIN = /^[A-Za-z0-9.-]+$/;

/**
 * `Set-Cookie` header value for a JWT: always `HttpOnly` (scripts, so XSS, can't read it), `Secure`
 * and `SameSite=Strict` (or `Lax`) so cross-site requests (CSRF) don't carry it. Throws on values that
 * could inject attributes.
 */
export function buildTokenCookie(name: string, value: string, options: TokenCookieOptions): string {
  if (!COOKIE_NAME.test(name)) throw new TypeError("Invalid cookie name");
  if (!/^[A-Za-z0-9._~+/=-]+$/.test(value)) throw new TypeError("Invalid cookie value: expected a JWT");
  const path = options.path ?? "/";
  if (!COOKIE_PATH.test(path)) throw new TypeError("Invalid cookie path");
  if (options.domain !== undefined && !COOKIE_DOMAIN.test(options.domain)) throw new TypeError("Invalid cookie domain");
  if (!Number.isFinite(options.maxAge) || options.maxAge < 0) throw new TypeError("maxAge must be a non-negative number of seconds");
  const sameSite = options.sameSite ?? "Strict";
  if (sameSite !== "Strict" && sameSite !== "Lax") throw new TypeError("sameSite must be Strict or Lax");
  return [
    `${name}=${value}`,
    `Path=${path}`,
    `Max-Age=${Math.floor(options.maxAge)}`,
    ...(options.domain ? [`Domain=${options.domain}`] : []),
    "HttpOnly",
    ...(options.secure === false ? [] : ["Secure"]),
    `SameSite=${sameSite}`,
  ].join("; ");
}

/** `Set-Cookie` value that deletes a cookie set with `buildTokenCookie` (use the same path/domain). */
export function clearTokenCookie(name: string, options: Pick<TokenCookieOptions, "path" | "domain" | "sameSite" | "secure"> = {}): string {
  return buildTokenCookie(name, "deleted", { ...options, maxAge: 0 }).replace("=deleted;", "=;");
}

/**
 * The two cookies for a web app's session: the access token (`dw_at`, sent everywhere) and the refresh
 * token (`dw_rt`, only sent to `refreshPath`). Both HttpOnly + Secure + SameSite.
 */
export function daywalkerCookies(
  tokens: { accessToken: string; refreshToken: string; expiresIn: number; refreshExpiresIn: number },
  options: { refreshPath?: string; sameSite?: "Strict" | "Lax"; secure?: boolean; domain?: string } = {}
): string[] {
  const common = { sameSite: options.sameSite, secure: options.secure, domain: options.domain };
  return [
    buildTokenCookie("dw_at", tokens.accessToken, { ...common, path: "/", maxAge: tokens.expiresIn }),
    buildTokenCookie("dw_rt", tokens.refreshToken, { ...common, path: options.refreshPath ?? "/api/auth/refresh", maxAge: tokens.refreshExpiresIn }),
  ];
}

/** The `user` object (public UUID, name, email) of an access token payload that was already verified. */
export function accessTokenUser(payload: Record<string, unknown>): AccessTokenUser | null {
  const u = payload.user;
  if (!u || typeof u !== "object") return null;
  const { id, name, email } = u as Record<string, unknown>;
  if (typeof id !== "string" || typeof email !== "string") return null;
  return { id, name: typeof name === "string" ? name : null, email };
}
