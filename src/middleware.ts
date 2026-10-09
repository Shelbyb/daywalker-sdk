import { daywalker, Daywalker } from "./client.js";
import type { TokenPayload, ValidateResult } from "./types.js";

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
      const status = result.status === 429 ? 429 : 401;
      const body = {
        error: result.error,
        message: result.message,
        retryAfter: result.retryAfter,
      };
      const headers = result.retryAfter ? { "Retry-After": String(result.retryAfter) } : undefined;

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
