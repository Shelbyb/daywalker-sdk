import { daywalker, Daywalker } from "./client.js";
import type { IncomingDpop, TokenPayload, ValidateResult } from "./types.js";

/** Longest Authorization / x-api-token / DPoP header read; longer ones are refused unparsed. */
export const MAX_AUTH_HEADER_LENGTH = 8_300;

export type Credentials =
  | { ok: true; token: string; dpop?: IncomingDpop }
  | { ok: false; message: string };

/**
 * Reads the caller's token from `Authorization: Bearer <token>`, `Authorization: DPoP <token>` (with its
 * `DPoP` proof header) or, when there is no Authorization header, `x-api-token`. An Authorization header
 * with any other scheme, a malformed or oversized header, or a header given twice is refused rather than
 * skipped, so a request can't pick which credential is checked. Shared by the Next, Web/Hono and Express
 * adapters.
 */
export function readCredentials(
  getHeader: (name: string) => string | string[] | null | undefined,
  request: { method: string; url: string }
): Credentials {
  const one = (name: string): string | undefined | null => {
    const v = getHeader(name);
    if (Array.isArray(v)) return v.length === 1 ? v[0] : null;
    return v ?? undefined;
  };
  const authorization = one("authorization");
  const apiToken = one("x-api-token");
  if (authorization === null || apiToken === null) return { ok: false, message: "Credentials header sent more than once" };
  if (authorization !== undefined && authorization !== "") {
    if (authorization.length > MAX_AUTH_HEADER_LENGTH) return { ok: false, message: "Authorization header is too long" };
    const m = /^(Bearer|DPoP) ([^\s,]+)$/i.exec(authorization.trim());
    if (!m) return { ok: false, message: "Authorization must be `Bearer <token>` or `DPoP <token>`" };
    if (m[1].toLowerCase() === "bearer") return { ok: true, token: m[2] };
    const proof = one("dpop");
    if (proof === null) return { ok: false, message: "DPoP header sent more than once" };
    if (proof !== undefined && proof.length > MAX_AUTH_HEADER_LENGTH) return { ok: false, message: "DPoP header is too long" };
    return { ok: true, token: m[2], dpop: { proof: proof?.trim(), method: request.method, url: request.url } };
  }
  if (apiToken !== undefined && apiToken.trim() !== "") {
    if (apiToken.length > MAX_AUTH_HEADER_LENGTH) return { ok: false, message: "x-api-token header is too long" };
    return { ok: true, token: apiToken.trim() };
  }
  return { ok: false, message: "Missing Authorization header or x-api-token" };
}

type ValidateFailure = Extract<ValidateResult, { ok: false }>;

/** Error codes that mean Daywalker Auth itself could not be reached or is degraded. */
const UNAVAILABLE_ERROR_CODES = new Set(["NETWORK_ERROR", "SERVICE_UNAVAILABLE"]);

export interface AuthFailureResponse {
  /**
   * 401 bad/expired/missing token or DPoP proof, 403 token not valid for this service, 429 rate limited,
   * 500 server misconfiguration, 503 auth service unavailable.
   */
  status: 401 | 403 | 429 | 500 | 503;
  error: string;
  message: string;
  retryAfter?: number;
}

/**
 * Maps a failed validation to the HTTP status an adapter should answer with. Outages (5xx,
 * network errors, SERVICE_UNAVAILABLE) become 503 rather than 401 so clients retry instead of
 * discarding a valid token; configuration errors become a 500 without their (internal) details.
 * Shared by the Next, Web/Hono and Express adapters.
 */
export function toAuthFailureResponse(result: ValidateFailure): AuthFailureResponse {
  const retryAfter = result.retryAfter && result.retryAfter > 0 ? result.retryAfter : undefined;
  if (result.error === "CONFIGURATION_ERROR") {
    return { status: 500, error: "CONFIGURATION_ERROR", message: "Authentication is not configured correctly on this server." };
  }
  if (result.status === 429 || result.error === "RATE_LIMITED") {
    return { status: 429, error: "RATE_LIMITED", message: result.message || "Rate limit exceeded", retryAfter };
  }
  if (result.status >= 500 || result.status === 0 || UNAVAILABLE_ERROR_CODES.has(result.error)) {
    return {
      status: 503,
      error: UNAVAILABLE_ERROR_CODES.has(result.error) ? result.error : "SERVICE_UNAVAILABLE",
      message: "Daywalker Auth is temporarily unavailable. Please retry.",
      retryAfter,
    };
  }
  if (result.status === 403) {
    return { status: 403, error: result.error || "FORBIDDEN", message: result.message || "Forbidden" };
  }
  return { status: 401, error: result.error || "INVALID_TOKEN", message: result.message || "Unauthorized" };
}

export interface DaywalkerMiddlewareOptions {
  client?: Daywalker;
  serviceSlug?: string;
  headerName?: string;
}

/**
 * Standard Web / Hono compatible middleware.
 * Works with Hono, standard Web Request/Response routers, and middleware pipelines.
 *
 * Example in Hono:
 *   import { Hono } from "hono";
 *   import { daywalkerAuth } from "@shelbyb/daywalker-sdk/middleware";
 *
 *   const app = new Hono();
 *   app.use("/api/*", daywalkerAuth());
 *   app.get("/api/me", (c) => c.json({ auth: c.get("auth") }));
 */
export function daywalkerAuth(options: DaywalkerMiddlewareOptions = {}) {
  const client = options.client ?? daywalker;
  const serviceSlug = options.serviceSlug;

  return async function daywalkerMiddleware(
    c: any,
    next: () => Promise<Response | void | undefined>
  ): Promise<Response | void> {
    let getHeader: (name: string) => string | string[] | null | undefined = () => undefined;
    let method = "GET";
    let url = "http://localhost/";
    const raw: unknown = c?.req?.raw ?? (c instanceof Request ? c : undefined);
    if (raw instanceof Request) {
      getHeader = (name) => raw.headers.get(name);
      method = raw.method;
      url = raw.url;
    } else if (typeof c?.req?.header === "function") {
      getHeader = (name) => c.req.header(name);
      method = String(c.req.method ?? method);
      url = String(c.req.url ?? url);
    } else if (c?.req?.headers instanceof Headers || c?.headers instanceof Headers) {
      const headers = (c.req?.headers ?? c.headers) as Headers;
      getHeader = (name) => headers.get(name);
      method = String(c.req?.method ?? c.method ?? method);
      url = String(c.req?.url ?? c.url ?? url);
    } else if (c?.req?.headers && typeof c.req.headers === "object") {
      const headers = c.req.headers as Record<string, string | string[] | undefined>;
      getHeader = (name) => {
        const key = Object.keys(headers).filter((k) => k.toLowerCase() === name);
        return key.length > 1 ? [String(headers[key[0]]), String(headers[key[1]])] : key.length === 1 ? headers[key[0]] : undefined;
      };
      method = String(c.req.method ?? method);
      url = String(c.req.url ?? url);
    }

    const credentials = readCredentials(getHeader, { method, url });
    if (!credentials.ok) {
      const body = { error: "INVALID_TOKEN", message: credentials.message };
      if (typeof c?.json === "function") {
        return c.json(body, 401);
      }
      return Response.json(body, { status: 401 });
    }

    const result = await client.validateToken(credentials.token, { serviceSlug, dpop: credentials.dpop });
    if (!result.ok) {
      const { status, ...body } = toAuthFailureResponse(result);
      const headers = body.retryAfter ? { "Retry-After": String(body.retryAfter) } : undefined;

      if (typeof c?.json === "function") {
        return c.json(body, status, headers);
      }
      return Response.json(body, { status, headers });
    }

    // Attach to context if available
    if (typeof c?.set === "function") {
      c.set("auth", result.data);
      c.set("daywalkerAuth", result.data);
    } else if (c) {
      c.auth = result.data;
    }

    return next();
  };
}

export { daywalkerAuth as daywalkerMiddleware };
