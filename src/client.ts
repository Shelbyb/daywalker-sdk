import { resolveConfig, type DaywalkerOptions, type ResolvedConfig } from "./config.js";
import { signRequest, KEYS_PATH, type PublicJwk } from "./signing.js";

export interface RateLimitWindow {
  limit: number;
  remaining: number;
  /** Unix seconds when `remaining` next increases */
  reset: number;
}

/** Body of POST /api/v1/tokens/validate */
export interface TokenValidation {
  valid: boolean;
  serviceSlug?: string;
  tokenId?: string;
  tokenName?: string;
  userId?: string;
  stage?: string;
  rateLimit?: RateLimitWindow;
  rateLimitHourly?: RateLimitWindow;
  retryAfter?: number;
  error?: string;
  message?: string;
}

export interface ValidationResult {
  valid: boolean;
  /** HTTP status from Daywalker, or 503 when it couldn't be reached */
  status: number;
  data: TokenValidation;
  /** Seconds to wait before retrying (429 responses) */
  retryAfter?: number;
  /** Whether the request carried a domain signature */
  signed: boolean;
}

export interface SelfCheckResult {
  ok: boolean;
  domain: string | null;
  keysUrl: string | null;
  signing: boolean;
  problems: string[];
}

export class DaywalkerError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly result?: ValidationResult
  ) {
    super(message);
    this.name = "DaywalkerError";
  }
}

export interface Daywalker {
  readonly config: ResolvedConfig;
  /**
   * Validate an API token (defaults to DAYWALKER_API_KEY) for a service (defaults to
   * DAYWALKER_SERVICE_SLUG). Successful results are cached briefly.
   */
  validateToken(options?: { token?: string; serviceSlug?: string; forceRefresh?: boolean }): Promise<ValidationResult>;
  /** Like validateToken, but throws DaywalkerError when the token isn't valid. */
  requireValidToken(options?: { token?: string; serviceSlug?: string }): Promise<ValidationResult>;
  /**
   * fetch() for any Daywalker Auth API path (e.g. "/api/v1/tokens/validate"), domain-signed
   * when a signing key and domain are configured. Pass the body as a string, or as an object
   * to send JSON.
   */
  fetch(path: string, init?: Omit<RequestInit, "body"> & { body?: string | object }): Promise<Response>;
  /** The JWKS document to serve at /.well-known/daywalker-keys.json */
  keys(): { keys: PublicJwk[] };
  /** Check configuration and that the domain serves this service's public key. */
  selfCheck(): Promise<SelfCheckResult>;
}

export function createDaywalker(options: DaywalkerOptions = {}): Daywalker {
  const config = resolveConfig(options);
  const doFetch = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 5000;
  const cacheTtlMs = options.cacheTtlMs ?? 60_000;
  const cache = new Map<string, { result: ValidationResult; expiresAt: number }>();
  const signing = Boolean(config.signingKey && config.domain);

  async function signedFetch(path: string, init: Omit<RequestInit, "body"> & { body?: string | object } = {}) {
    const url = new URL(path, config.authUrl);
    const method = (init.method ?? (init.body !== undefined ? "POST" : "GET")).toUpperCase();
    const body = init.body === undefined ? "" : typeof init.body === "string" ? init.body : JSON.stringify(init.body);
    const headers = new Headers(init.headers);
    if (init.body !== undefined && typeof init.body !== "string" && !headers.has("content-type")) {
      headers.set("content-type", "application/json");
    }
    if (!headers.has("accept")) headers.set("accept", "application/json");
    if (config.domain) {
      // A hint for DNS-based allowlist checks; the signature below is the actual proof
      headers.set("x-caller-origin", `https://${config.domain}`);
    }
    if (signing) {
      for (const [k, v] of Object.entries(
        signRequest({ method, path: url.pathname, domain: config.domain!, body, key: config.signingKey! })
      )) {
        headers.set(k, v);
      }
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      return await doFetch(url, {
        ...init,
        method,
        headers,
        body: method === "GET" || method === "HEAD" ? undefined : body,
        signal: init.signal ?? controller.signal,
      });
    } finally {
      clearTimeout(timer);
    }
  }

  async function validateToken(opts: { token?: string; serviceSlug?: string; forceRefresh?: boolean } = {}) {
    const token = opts.token ?? config.apiKey;
    const serviceSlug = (opts.serviceSlug ?? config.serviceSlug ?? "").toLowerCase();
    if (!token || !serviceSlug) {
      const message = !token ? "DAYWALKER_API_KEY is not set" : "DAYWALKER_SERVICE_SLUG is not set";
      return { valid: false, status: 500, signed: false, data: { valid: false, error: "Configuration Error", message } };
    }

    const cacheKey = `${serviceSlug}:${token}`;
    const cached = cache.get(cacheKey);
    if (!opts.forceRefresh && cached && cached.expiresAt > Date.now()) return cached.result;

    let result: ValidationResult;
    try {
      const res = await signedFetch("/api/v1/tokens/validate", { method: "POST", body: { token, serviceSlug } });
      const data = (await res.json().catch(() => ({ valid: false }))) as TokenValidation;
      const retryAfter = Number(res.headers.get("retry-after")) || data.retryAfter || undefined;
      result = { valid: res.ok && data.valid === true, status: res.status, data, retryAfter, signed: signing };
    } catch (err) {
      const timedOut = (err as Error).name === "AbortError";
      result = {
        valid: false,
        status: 503,
        signed: signing,
        data: {
          valid: false,
          error: timedOut ? "Request Timeout" : "Service Unavailable",
          message: timedOut ? "Daywalker Auth did not respond in time" : `Could not reach Daywalker Auth: ${(err as Error).message}`,
        },
      };
    }

    if (result.valid && cacheTtlMs > 0) cache.set(cacheKey, { result, expiresAt: Date.now() + cacheTtlMs });
    else cache.delete(cacheKey);
    if (!result.valid && result.status !== 503) {
      console.warn(`[daywalker] Token validation failed (${result.status}): ${result.data.message ?? result.data.error}`);
    }
    return result;
  }

  function keys() {
    const list = [config.signingKey, config.previousSigningKey]
      .filter((k): k is NonNullable<typeof k> => Boolean(k))
      .map((k) => k.publicJwk);
    return { keys: list.filter((k, i) => list.findIndex((o) => o.kid === k.kid) === i) };
  }

  async function selfCheck(): Promise<SelfCheckResult> {
    const problems = [...config.problems];
    if (!config.signingKey) problems.push("DAYWALKER_SIGNING_KEY is not set: requests are unsigned, so domain allowlists can't match");
    const keysUrl = config.domain ? `https://${config.domain}${KEYS_PATH}` : null;
    if (keysUrl && config.signingKey) {
      try {
        const res = await doFetch(keysUrl, { headers: { accept: "application/json" }, redirect: "manual" });
        if (res.status !== 200) {
          problems.push(`${keysUrl} returned HTTP ${res.status} (it must serve the key directly, without redirects)`);
        } else {
          const doc = (await res.json().catch(() => null)) as { keys?: { kid?: string }[] } | null;
          if (!doc?.keys?.some((k) => k.kid === config.signingKey!.publicJwk.kid)) {
            problems.push(`${keysUrl} doesn't publish this service's current key (kid ${config.signingKey.publicJwk.kid})`);
          }
        }
      } catch (err) {
        problems.push(`Could not fetch ${keysUrl}: ${(err as Error).message}`);
      }
    }
    return { ok: problems.length === 0, domain: config.domain, keysUrl, signing, problems };
  }

  return {
    config,
    validateToken,
    async requireValidToken(opts = {}) {
      const result = await validateToken(opts);
      if (!result.valid) throw new DaywalkerError(result.data.message ?? "Token validation failed", result.status, result);
      return result;
    },
    fetch: signedFetch,
    keys,
    selfCheck,
  };
}

let shared: Daywalker | null = null;
/** A process-wide client configured from environment variables. */
export function daywalker(): Daywalker {
  shared ??= createDaywalker();
  return shared;
}
