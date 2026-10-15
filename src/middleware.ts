import { daywalker, Daywalker } from "./client.js";
import type { TokenPayload, ValidateResult } from "./types.js";

type ValidateFailure = Extract<ValidateResult, { ok: false }>;

/** Error codes that mean Daywalker Auth itself could not be reached or is degraded. */
const UNAVAILABLE_ERROR_CODES = new Set(["NETWORK_ERROR", "SERVICE_UNAVAILABLE"]);

export interface AuthFailureResponse {
  /** 401 bad/expired/missing token, 429 rate limited, 500 server misconfiguration, 503 auth service unavailable. */
  status: 401 | 429 | 500 | 503;
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
    let authHeader: string | undefined;
    let apiTokenHeader: string | undefined;

    if (typeof c?.req?.header === "function") {
      authHeader = c.req.header("authorization");
      apiTokenHeader = c.req.header("x-api-token");
    } else if (c?.req?.headers instanceof Headers || c?.headers instanceof Headers) {
      const headers = (c.req?.headers ?? c.headers) as Headers;
      authHeader = headers.get("authorization") ?? undefined;
      apiTokenHeader = headers.get("x-api-token") ?? undefined;
    } else if (typeof c?.req?.headers === "object" || typeof c?.headers === "object") {
      const headers = c.req?.headers ?? c.headers;
      authHeader = headers["authorization"] || headers["Authorization"];
      apiTokenHeader = headers["x-api-token"] || headers["X-Api-Token"];
    }

    let token: string | null = null;
    if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
      token = authHeader.slice(7).trim();
    } else if (apiTokenHeader) {
      token = apiTokenHeader.trim();
    }

    if (!token) {
      if (typeof c?.json === "function") {
        return c.json(
          { error: "INVALID_TOKEN", message: "Missing Authorization header or x-api-token" },
          401
        );
      }
      return Response.json(
        { error: "INVALID_TOKEN", message: "Missing Authorization header or x-api-token" },
        { status: 401 }
      );
    }

    const result = await client.validateToken(token, { serviceSlug });
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
