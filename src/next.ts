import { daywalker, Daywalker } from "./client.js";
import type { TokenPayload, ValidateResult } from "./types.js";

/**
 * Real Server Action IDs are hex hashes. Scanners probing for CVE-2025-55182 (React2Shell)
 * send junk like `Next-Action: x`, which Next.js rejects with an internal error.
 * Dropping them up front protects application logs and server resources.
 */
export const SERVER_ACTION_ID_PATTERN = /^[0-9a-f]{40,}$/i;

export const DEFAULT_BYPASS_PATHS = [
  "/api/health",
  "/healthz",
  "/favicon.ico",
  "/robots.txt",
  "/sitemap.xml",
];

export interface NextMiddlewareOptions {
  client?: Daywalker;
  serviceSlug?: string;
  bypassPaths?: string[];
  errorPath?: string;
  homePath?: string;
  protectApiOnly?: boolean;
  validateServerActions?: boolean;
  allowedHosts?: string[];
}

/**
 * Sanitizes open redirect path parameter (`from`).
 * Prevents protocol-relative URLs (`//evil.com`), backslashes (`/\evil.com`), and control characters.
 */
export function sanitizeRedirectPath(path: string): string | null {
  if (!path || typeof path !== "string") return null;
  const clean = path.trim().replace(/[\r\n\0]/g, "");
  if (!clean.startsWith("/") || clean.startsWith("//") || clean.startsWith("/\\")) {
    return null;
  }
  return clean;
}

function extractToken(req: Request): string | null {
  const authHeader = req.headers.get("authorization");
  if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
    return authHeader.slice(7).trim();
  }
  const apiTokenHeader = req.headers.get("x-api-token");
  if (apiTokenHeader) {
    return apiTokenHeader.trim();
  }
  return null;
}

/**
 * Hardened Next.js Middleware for root `middleware.ts`.
 *
 * Implements:
 * 1. Server Action probe defense (CVE-2025-55182 scanner mitigation)
 * 2. Static asset and health check bypass
 * 3. Self-healing service error page routing with `from` back-redirect
 * 4. Distinct handling for API routes (JSON + CORS) vs UI pages (redirect)
 *
 * Example:
 *   // middleware.ts
 *   import { createDaywalkerMiddleware } from "@shelbyb/daywalker-sdk/next";
 *
 *   export const middleware = createDaywalkerMiddleware();
 *
 *   export const config = {
 *     matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
 *   };
 */
export function createDaywalkerMiddleware(options: NextMiddlewareOptions = {}) {
  const client = options.client ?? daywalker;
  const bypassPaths = options.bypassPaths ?? DEFAULT_BYPASS_PATHS;
  const errorPath = options.errorPath ?? "/service-error";
  const homePath = options.homePath ?? "/";
  const validateServerActions = options.validateServerActions ?? true;

  return async function middleware(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;
    const search = url.search;

    // Host header validation if allowedHosts configured
    if (options.allowedHosts && options.allowedHosts.length > 0) {
      const host = request.headers.get("host")?.toLowerCase().replace(/:\d+$/, "");
      if (host && !options.allowedHosts.some((h) => h.toLowerCase() === host)) {
        return Response.json(
          { error: "Forbidden", message: "Invalid host header." },
          { status: 403 }
        );
      }
    }

    // 0. Reject malformed Server Action requests before routing or auth checks
    if (validateServerActions) {
      const actionId = request.headers.get("next-action");
      if (actionId !== null && (actionId.length > 256 || !SERVER_ACTION_ID_PATTERN.test(actionId.trim()))) {
        return Response.json(
          { error: "Bad Request", message: "Invalid Server Action request." },
          { status: 400 }
        );
      }
    }

    // 1. Bypass static files and health check probes
    if (
      bypassPaths.some((path) => pathname === path || pathname.startsWith(`${path}/`)) ||
      pathname.startsWith("/_next") ||
      (pathname.includes(".") && !pathname.endsWith(".json"))
    ) {
      return (globalThis as any).NextResponse?.next
        ? (globalThis as any).NextResponse.next()
        : new Response(null, { headers: { "x-middleware-next": "1" } });
    }

    // 2. Validate token (from request header, or service's configured DAYWALKER_API_KEY)
    const incomingToken = extractToken(request);
    const authResult: ValidateResult = await client.validateToken(
      incomingToken ? { token: incomingToken, serviceSlug: options.serviceSlug } : { serviceSlug: options.serviceSlug }
    );

    // 3. Handle service error page route
    if (pathname === errorPath) {
      if (authResult.ok) {
        // If the service token is now valid, heal/redirect back to home or referer
        const redirectUrl = new URL(homePath, request.url);
        return (globalThis as any).NextResponse?.redirect
          ? (globalThis as any).NextResponse.redirect(redirectUrl)
          : Response.redirect(redirectUrl.toString(), 307);
      }
      // Allow rendering the error page
      return (globalThis as any).NextResponse?.next
        ? (globalThis as any).NextResponse.next()
        : new Response(null, { headers: { "x-middleware-next": "1" } });
    }

    // 4. Handle invalid token for all other routes
    if (!authResult.ok) {
      // API routes: return JSON error response
      if (pathname.startsWith("/api/")) {
        return Response.json(
          {
            error: authResult.error || "Unauthorized",
            message: authResult.message || "Service authorization check failed with Daywalker Auth.",
            retryAfter: authResult.retryAfter,
          },
          {
            status: authResult.status || 401,
            headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
              "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Token",
              ...(authResult.retryAfter ? { "Retry-After": String(authResult.retryAfter) } : {}),
            },
          }
        );
      }

      // If user only wanted API protection, allow web routes through
      if (options.protectApiOnly) {
        return (globalThis as any).NextResponse?.next
          ? (globalThis as any).NextResponse.next()
          : new Response(null, { headers: { "x-middleware-next": "1" } });
      }

      // Web UI routes: redirect to diagnostic service error screen
      const redirectUrl = new URL(errorPath, request.url);
      redirectUrl.searchParams.set("error", authResult.error || "Unauthorized");
      redirectUrl.searchParams.set("message", authResult.message || "Service authorization check failed.");
      redirectUrl.searchParams.set("status", String(authResult.status || 401));
      if (pathname !== "/" || search) {
        const rawTarget = `${pathname}${search}`;
        const sanitized = sanitizeRedirectPath(rawTarget);
        if (sanitized) {
          redirectUrl.searchParams.set("from", sanitized);
        }
      }

      return (globalThis as any).NextResponse?.redirect
        ? (globalThis as any).NextResponse.redirect(redirectUrl)
        : Response.redirect(redirectUrl.toString(), 307);
    }

    return (globalThis as any).NextResponse?.next
      ? (globalThis as any).NextResponse.next()
      : new Response(null, { headers: { "x-middleware-next": "1" } });
  };
}

/**
 * Next.js App Router route handler wrapper with Daywalker token validation.
 * Extracts `Authorization: Bearer <token>` or `x-api-token`, validates via client,
 * returns 401/429 JSON response on error, or passes validated `auth` payload in context.
 *
 * Example:
 *   // app/api/protected/route.ts
 *   import { withDaywalkerAuth } from "@shelbyb/daywalker-sdk/next";
 *
 *   export const POST = withDaywalkerAuth(async (req, { auth }) => {
 *     return Response.json({ message: "Hello " + auth.serviceSlug, auth });
 *   });
 */
export function withDaywalkerAuth<Context extends Record<string, unknown> = Record<string, unknown>>(
  handler: (req: Request, context: Context & { auth: TokenPayload }) => Promise<Response>,
  clientOrOptions?: Daywalker | { client?: Daywalker; serviceSlug?: string }
): (req: Request, context?: Context) => Promise<Response> {
  const client =
    clientOrOptions instanceof Daywalker
      ? clientOrOptions
      : clientOrOptions?.client ?? daywalker;
  const serviceSlug =
    !(clientOrOptions instanceof Daywalker) ? clientOrOptions?.serviceSlug : undefined;

  return async function daywalkerAuthHandler(req: Request, context?: Context): Promise<Response> {
    const token = extractToken(req);
    if (!token) {
      return Response.json(
        { error: "INVALID_TOKEN", message: "Missing Authorization header or x-api-token" },
        { status: 401 }
      );
    }

    const result = await client.validateToken(token, { serviceSlug });
    if (!result.ok) {
      return Response.json(
        { error: result.error, message: result.message, retryAfter: result.retryAfter },
        {
          status: result.status === 429 ? 429 : 401,
          headers: result.retryAfter ? { "Retry-After": String(result.retryAfter) } : undefined,
        }
      );
    }

    const mergedContext = {
      ...(context ?? ({} as Context)),
      auth: result.data,
    };

    return handler(req, mergedContext);
  };
}
