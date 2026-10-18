import { daywalker, Daywalker } from "./client.js";
import { toAuthFailureResponse } from "./middleware.js";
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

/**
 * A suggested value for the opt-in `staticFileExtensions` option. It is NOT applied by default:
 * an extension says nothing about whether a route is public (`/users/123.js` can be a dynamic page).
 * Prefer excluding public files with Next's `matcher` (see `createDaywalkerMiddleware`).
 */
export const STATIC_FILE_EXTENSIONS = /\.(?:js|css|png|jpe?g|gif|webp|avif|svg|ico|woff2?|map|txt)$/i;

/**
 * Decodes and normalizes a URL pathname the way a router sees it: percent-decoded once, `//`
 * collapsed and `.`/`..` segments resolved. Returns null (never bypass auth) for malformed
 * encoding, encoded slashes/backslashes, raw backslashes or control characters.
 */
export function normalizePathname(pathname: string): string | null {
  if (typeof pathname !== "string" || !pathname.startsWith("/")) return null;
  if (pathname.includes("\\") || /%(?:2f|5c)/i.test(pathname)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    return null;
  }
  if (/[\u0000-\u001f\u007f\\]/.test(decoded)) return null;
  const segments: string[] = [];
  for (const segment of decoded.split("/")) {
    if (segment === "" || segment === ".") continue;
    if (segment === "..") segments.pop();
    else segments.push(segment);
  }
  const trailingSlash = segments.length > 0 && /\/\.{0,2}$/.test(decoded);
  return `/${segments.join("/")}${trailingSlash ? "/" : ""}`;
}

function isApiPath(pathname: string): boolean {
  return pathname === "/api" || pathname.startsWith("/api/");
}

function extensionMatcher(extensions: RegExp | readonly string[] | undefined): ((pathname: string) => boolean) | null {
  if (!extensions) return null;
  if (extensions instanceof RegExp) {
    // Copy without the stateful g/y flags so repeated .test() calls are consistent.
    const re = new RegExp(extensions.source, extensions.flags.replace(/[gy]/g, ""));
    return (pathname) => re.test(pathname);
  }
  const list = extensions.map((e) => e.replace(/^\./, "").toLowerCase()).filter(Boolean);
  if (list.length === 0) return null;
  return (pathname) => {
    const last = pathname.slice(pathname.lastIndexOf("/") + 1).toLowerCase();
    return list.some((ext) => last.endsWith(`.${ext}`) && last.length > ext.length + 1);
  };
}

/** `pathname` must already be normalized. */
function isBuiltInStaticPath(pathname: string): boolean {
  return pathname.startsWith("/_next/static/") || pathname === "/_next/image" || pathname.startsWith("/_next/image/") || pathname === "/favicon.ico";
}

function isStaticNormalized(pathname: string, matchesExtension: ((pathname: string) => boolean) | null): boolean {
  if (isApiPath(pathname)) return false;
  if (isBuiltInStaticPath(pathname)) return true;
  if (pathname.startsWith("/_next/")) return false;
  return matchesExtension ? matchesExtension(pathname) : false;
}

/**
 * Static assets that skip auth: Next's build output (`/_next/static/`), image optimizer
 * (`/_next/image`) and `/favicon.ico`. Files matching `staticFileExtensions` are included only when
 * that list is passed explicitly. The path is decoded and normalized first; `/_next/data/`
 * (getServerSideProps JSON) and `/api` / `/api/*` are never static.
 */
export function isStaticAssetPath(pathname: string, staticFileExtensions?: RegExp | readonly string[]): boolean {
  const normalized = normalizePathname(pathname);
  if (normalized === null) return false;
  return isStaticNormalized(normalized, extensionMatcher(staticFileExtensions));
}

export interface NextMiddlewareOptions {
  client?: Daywalker;
  serviceSlug?: string;
  /**
   * Public paths that skip auth (exact match or `path/` prefix, compared against the decoded,
   * normalized pathname). Defaults to `DEFAULT_BYPASS_PATHS`. Prefer Next's `matcher` config to keep
   * public routes from reaching the middleware at all.
   */
  bypassPaths?: string[];
  /**
   * Opt-in: also skip auth for (non-`/api`, non-`/_next/`) paths ending in one of these extensions,
   * e.g. `STATIC_FILE_EXTENSIONS` or `["png", "css"]`. Off by default, because a dynamic route such
   * as `/users/[id]` also answers `/users/123.js`. Prefer a `matcher` that excludes `public/` files.
   */
  staticFileExtensions?: RegExp | readonly string[];
  errorPath?: string;
  homePath?: string;
  /** Only enforce auth on `/api` and `/api/*`; other routes pass through. */
  protectApiOnly?: boolean;
  validateServerActions?: boolean;
  /** When set, requests whose Host header is missing or not listed get a 403. */
  allowedHosts?: string[];
}

/** Options for the Next.js 16+ `proxy.ts` aliases (identical to `NextMiddlewareOptions`). */
export type NextProxyOptions = NextMiddlewareOptions;

const REDIRECT_ORIGIN = "https://redirect-check.invalid";

/**
 * Sanitizes open redirect path parameter (`from`).
 * Accepts only same-origin relative paths: rejects protocol-relative URLs (`//evil.com`), any
 * backslash, whitespace or control character (browsers strip tabs/newlines, so `/\t/evil.com` would
 * become `//evil.com`), and anything that resolves to another origin.
 */
export function sanitizeRedirectPath(path: string): string | null {
  if (!path || typeof path !== "string") return null;
  if (/[\s\u0000-\u001f\u007f-\u009f\\]/.test(path)) return null;
  if (!path.startsWith("/") || path.startsWith("//")) return null;
  let resolved: URL;
  try {
    resolved = new URL(path, REDIRECT_ORIGIN);
  } catch {
    return null;
  }
  if (resolved.origin !== REDIRECT_ORIGIN || !resolved.pathname.startsWith("/") || resolved.pathname.startsWith("//")) {
    return null;
  }
  return path;
}

/** Error codes the error page may receive in its `error` query parameter. */
const REDIRECT_ERROR_CODES = new Set([
  "INVALID_TOKEN",
  "EXPIRED",
  "REVOKED",
  "RATE_LIMITED",
  "NETWORK_ERROR",
  "SERVICE_UNAVAILABLE",
  "CONFIGURATION_ERROR",
]);

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
 * Only `/_next/static/`, `/_next/image`, `/favicon.ico` and `bypassPaths` skip auth by default.
 * Exclude other public files with Next's `matcher` (recommended) or opt into `staticFileExtensions`.
 *
 * Example:
 *   // middleware.ts (Next.js 16+: proxy.ts, `export const proxy = createDaywalkerProxy();`)
 *   import { createDaywalkerMiddleware } from "@shelbyb/daywalker-sdk/next";
 *
 *   export const middleware = createDaywalkerMiddleware();
 *
 *   export const config = {
 *     matcher: ["/((?!_next/static|_next/image|favicon.ico|images/).*)"],
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
 * Service health gate: checks that this service's OAuth client credentials still get an access token
 * covering its service (not the caller's token) and routes every request to `errorPath` while they don't,
 * redirecting back once it heals.
 * It does NOT authenticate callers; use `createDaywalkerMiddleware` or `withDaywalkerAuth` for that.
 */
export function createDaywalkerServiceHealthMiddleware(options: NextMiddlewareOptions = {}) {
  const client = options.client ?? daywalker;
  return buildMiddleware(options, () => client.validateServiceCredentials({ serviceSlug: options.serviceSlug }));
}

function buildMiddleware(options: NextMiddlewareOptions, authenticate: (request: Request) => Promise<ValidateResult>) {
  const bypassPaths = options.bypassPaths ?? DEFAULT_BYPASS_PATHS;
  const errorPath = options.errorPath ?? "/service-error";
  const homePath = options.homePath ?? "/";
  const validateServerActions = options.validateServerActions ?? true;
  const matchesExtension = extensionMatcher(options.staticFileExtensions);
  const normalizedErrorPath = normalizePathname(errorPath) ?? errorPath;

  return async function middleware(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const rawPathname = url.pathname;
    const search = url.search;
    // Routing decisions use the decoded, normalized path (`/%61pi/x` is `/api/x`). A path that
    // cannot be normalized safely (encoded slashes, bad encoding) is never bypassed and is treated
    // as an API route, so it is authenticated even with `protectApiOnly`.
    const pathname = normalizePathname(rawPathname);
    const isApi = pathname === null || isApiPath(pathname);

    // Host header validation if allowedHosts configured; a missing Host is refused too.
    if (options.allowedHosts && options.allowedHosts.length > 0) {
      const host = request.headers.get("host")?.trim().toLowerCase().replace(/:\d+$/, "");
      if (!host || !options.allowedHosts.some((h) => h.toLowerCase() === host)) {
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
      pathname !== null &&
      (bypassPaths.some((path) => pathname === path || pathname.startsWith(`${path}/`)) || isStaticNormalized(pathname, matchesExtension))
    ) {
      return (globalThis as any).NextResponse?.next
        ? (globalThis as any).NextResponse.next()
        : new Response(null, { headers: { "x-middleware-next": "1" } });
    }

    // 2. Authenticate (caller's token, or the service key for the health gate)
    const authResult: ValidateResult = await authenticate(request);

    // 3. Handle service error page route
    if (pathname === normalizedErrorPath) {
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
      const failure = toAuthFailureResponse(authResult);
      // API routes: return JSON error response
      if (isApi) {
        return Response.json(
          {
            error: failure.error,
            message: failure.message || "Service authorization check failed with Daywalker Auth.",
            retryAfter: failure.retryAfter,
          },
          {
            status: failure.status,
            headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
              "Access-Control-Allow-Headers": "Content-Type, Authorization, X-Api-Token",
              ...(failure.retryAfter ? { "Retry-After": String(failure.retryAfter) } : {}),
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

      // Web UI routes: redirect to diagnostic service error screen. Only a fixed error code and
      // status are passed: the free-text message may carry server details and would let anyone
      // put arbitrary text on the error page via a crafted link.
      const redirectUrl = new URL(errorPath, request.url);
      redirectUrl.searchParams.set("error", REDIRECT_ERROR_CODES.has(failure.error) ? failure.error : "UNAUTHORIZED");
      redirectUrl.searchParams.set("status", String(failure.status));
      if (rawPathname !== "/" || search) {
        const rawTarget = `${rawPathname}${search}`;
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
 * returns a JSON error on failure (401 bad token, 429 rate limited, 503 Daywalker Auth unavailable,
 * 500 misconfiguration), or passes validated `auth` payload in context.
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
      const { status, ...body } = toAuthFailureResponse(result);
      return Response.json(body, {
        status,
        headers: body.retryAfter ? { "Retry-After": String(body.retryAfter) } : undefined,
      });
    }

    const mergedContext = {
      ...(context ?? ({} as Context)),
      auth: result.data,
    };

    return handler(req, mergedContext);
  };
}

/**
 * Next.js 16 renamed `middleware.ts` to `proxy.ts` (export `proxy` instead of `middleware`).
 * These aliases are identical to the `*Middleware` factories, which remain supported:
 *
 *   // proxy.ts
 *   import { createDaywalkerProxy } from "@shelbyb/daywalker-sdk/next";
 *   export const proxy = createDaywalkerProxy();
 *   export const config = { matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"] };
 */
export const createDaywalkerProxy = createDaywalkerMiddleware;
export const createDaywalkerServiceHealthProxy = createDaywalkerServiceHealthMiddleware;
