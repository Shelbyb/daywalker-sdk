import { daywalker, Daywalker } from "./client.js";
import { toAuthFailureResponse } from "./middleware.js";
import type { TokenPayload } from "./types.js";

interface Req {
  method?: string;
  path?: string;
  url?: string;
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
    const getHeader = (name: string): string | undefined => {
      if (typeof req.get === "function") return req.get(name);
      if (req.headers) {
        const val = req.headers[name.toLowerCase()] ?? req.headers[name];
        return Array.isArray(val) ? val[0] : val;
      }
      return undefined;
    };

    const authHeader = getHeader("authorization");
    const apiTokenHeader = getHeader("x-api-token");

    let token: string | null = null;
    if (authHeader && authHeader.toLowerCase().startsWith("bearer ")) {
      token = authHeader.slice(7).trim();
    } else if (apiTokenHeader) {
      token = apiTokenHeader.trim();
    }

    if (!token) {
      if (typeof res.status === "function" && typeof res.json === "function") {
        res.status(401).json({ error: "INVALID_TOKEN", message: "Missing Authorization header or x-api-token" });
        return;
      }
      res.statusCode = 401;
      res.setHeader("Content-Type", "application/json");
      res.end(JSON.stringify({ error: "INVALID_TOKEN", message: "Missing Authorization header or x-api-token" }));
      return;
    }

    const result = await client.validateToken(token, { serviceSlug });
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

export function daywalkerKeys(client: Daywalker = daywalker) {
  return async (req: Req, res: Res, next?: () => void) => {
    const path = req.path ?? (req.url ?? "").split("?")[0];
    if ((req.method ?? "GET") === "GET" && path === "/.well-known/daywalker-keys.json") {
      const keysDoc = await client.keys();
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", "public, max-age=300");
      res.end(JSON.stringify(keysDoc));
      return;
    }
    next?.();
  };
}
