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

/** File extensions treated as static assets (outside /api/) and passed through without auth. */
export const STATIC_FILE_EXTENSIONS = /\.(?:js|css|png|jpe?g|gif|webp|avif|svg|ico|woff2?|map|txt)$/i;

/**
 * Static assets that skip auth: Next's build output and image optimizer, the favicon, and files with
 * an allowlisted extension. `/_next/data/` (getServerSideProps JSON) and `/api/*` are never static.
 */
export function isStaticAssetPath(pathname: string): boolean {
  if (pathname === "/api" || pathname.startsWith("/api/")) return false;
  if (pathname.startsWith("/_next/static/") || pathname === "/_next/image" || pathname.startsWith("/_next/image/")) return true;
  if (pathname === "/favicon.ico") return true;
  if (pathname.startsWith("/_next/")) return false;
  return STATIC_FILE_EXTENSIONS.test(pathname);
}

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
 * 3. Per-request token auth: requests without `Authorization: Bearer` / `x-api-token` get 401
 * 4. Distinct handling for API routes (JSON + CORS) vs UI pages (redirect to `errorPath` with `from`)
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
  return buildMiddleware(options, async (request) => {
    const token = extractToken(request);
    if (!token) {
      return { ok: false, error: "INVALID_TOKEN", status: 401, message: "Missing Authorization header or x-api-token" };
    }
    return client.validateToken(token, { serviceSlug: options.serviceSlug });
  });
}

/**
 * Service health gate: checks this service's own DAYWALKER_API_KEY (not the caller's token) and
 * routes every request to `errorPath` while it is invalid, redirecting back once it heals.
 * It does NOT authenticate callers; use `createDaywalkerMiddleware` or `withDaywalkerAuth` for that.
 */
export function createDaywalkerServiceHealthMiddleware(options: NextMiddlewareOptions = {}) {
  const client = options.client ?? daywalker;
  return buildMiddleware(options, () => client.validateServiceKey({ serviceSlug: options.serviceSlug }));
}

function buildMiddleware(options: NextMiddlewareOptions, authenticate: (request: Request) => Promise<ValidateResult>) {
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
    if (bypassPaths.some((path) => pathname === path || pathname.startsWith(`${path}/`)) || isStaticAssetPath(pathname)) {
      return (globalThis as any).NextResponse?.next
        ? (globalThis as any).NextResponse.next()
        : new Response(null, { headers: { "x-middleware-next": "1" } });
    }

    // 2. Authenticate (caller's token, or the service key for the health gate)
    const authResult: ValidateResult = await authenticate(request);

    // 3. Handle service error page route
    if (pathname === errorPath) {
      if (authResult.ok) {
        // Authorized again: heal/redirect back to home
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
