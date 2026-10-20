import { daywalker, Daywalker } from "./client.js";
import { readCredentials, toAuthFailureResponse } from "./middleware.js";
import type { TokenPayload, ValidateResult } from "./types.js";

interface Req {
  method?: string;
  path?: string;
  url?: string;
  originalUrl?: string;
  protocol?: string;
  headers?: Record<string, string | string[] | undefined>;
  get?: (name: string) => string | undefined;
  auth?: TokenPayload;
}

interface Res {
  setHeader(name: string, value: string): unknown;
  status(code: number): Res;
  json(body: unknown): unknown;
  statusCode?: number;
  end(body?: string): unknown;
}

/**
 * Express / Connect / Node http middleware that validates incoming Daywalker tokens.
 */
export function daywalkerAuth(options: { client?: Daywalker; serviceSlug?: string } = {}) {
  const client = options.client ?? daywalker;
  const serviceSlug = options.serviceSlug;

  return async (req: Req, res: Res, next?: (err?: unknown) => void) => {
    const getHeader = (name: string): string | string[] | undefined => {
      if (req.headers) return req.headers[name.toLowerCase()];
      if (typeof req.get === "function") return req.get(name);
      return undefined;
    };
    const host = typeof getHeader("host") === "string" ? (getHeader("host") as string) : "localhost";
    // The origin only matters for DPoP proofs, and is replaced by the client's `publicOrigin` when set.
    const url = `${req.protocol === "https" ? "https" : "http"}://${/^[A-Za-z0-9.:[\]-]+$/.test(host) ? host : "localhost"}${req.originalUrl ?? req.url ?? "/"}`;
    const credentials = readCredentials(getHeader, { method: req.method ?? "GET", url });

    if (!credentials.ok) {
      const body = { error: "INVALID_TOKEN", message: credentials.message };
      if (typeof res.status === "function" && typeof res.json === "function") {
        res.status(401).json(body);
        return;
      }
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(body));
      return;
    }

    let result: ValidateResult;
    try {
      result = await client.validateToken(credentials.token, { serviceSlug, dpop: credentials.dpop });
    } catch {
      // Express 4 doesn't catch async rejections: fail closed with a generic 503 instead of crashing or hanging.
      result = { ok: false, error: "SERVICE_UNAVAILABLE", status: 503, message: "Token validation failed" };
    }
    if (!result.ok) {
      const { status, ...body } = toAuthFailureResponse(result);
      if (body.retryAfter) {
        res.setHeader("Retry-After", String(body.retryAfter));
      }
      if (typeof res.status === "function" && typeof res.json === "function") {
        res.status(status).json(body);
        return;
      }
      res.statusCode = status;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify(body));
      return;
    }

    req.auth = result.data;
    next?.();
  };
}
