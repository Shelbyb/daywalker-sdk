import { assertSecureUrl } from "../secure-url.js";
import { SDK_VERSION } from "../flags/common/version.js";

/**
 * Typed client for the DevPulse management REST API (/api/v1), built only on fetch so it runs in
 * Node, Deno, Bun, Cloudflare Workers and browsers (never ship client credentials to a browser).
 *
 * - OAuth 2.0 client credentials at /oauth/token (HTTP Basic), cached and refreshed early.
 * - Errors are RFC 9457 problem details (`ApiProblemError`).
 * - Cursor pagination follows the RFC 8288 `Link: <…>; rel="next"` header.
 * - Retries 429 and 503 with exponential backoff, honoring `Retry-After`.
 * - `If-Match` support for optimistic concurrency (412 problems).
 * - Secrets only ever travel in headers or the request body, never in a URL; the Link header can
 *   never send the bearer token to another origin.
 */

export type ApiClientOptions = {
  /** Your DevPulse URL, e.g. https://devpulse.example.com (https required except on localhost). */
  host: string;
  clientId: string;
  clientSecret: string;
  /** Space-separated scopes to request. Default: everything the API client is allowed. */
  scope?: string;
  /** Refresh the token this many seconds before it expires. Default 60. */
  refreshSkewSeconds?: number;
  /** Retries after a 429/503 (or a 401 token refresh does not count). Default 3. */
  maxRetries?: number;
  /** First backoff delay in ms when there is no Retry-After; doubles each retry, with jitter. Default 500. */
  retryBaseMs?: number;
  /** Never wait longer than this between retries, in ms. Default 30000. */
  maxRetryDelayMs?: number;
  /** Per-attempt timeout in ms. Default 30000; 0 disables. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  /** Test seams. */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
  random?: () => number;
};

export type ProblemDetails = {
  type?: string;
  title?: string;
  status?: number;
  detail?: string;
  instance?: string;
  errors?: { pointer?: string; detail?: string }[];
  [extension: string]: unknown;
};

/** A non-2xx API response (RFC 9457). Extension members (e.g. `requiredPlan`) are on `problem`. */
export class ApiProblemError extends Error {
  readonly status: number;
  readonly problem: ProblemDetails;
  /** Seconds from Retry-After on 429/503, when sent. */
  readonly retryAfter?: number;
  readonly headers: Headers;
  constructor(status: number, problem: ProblemDetails, headers: Headers, retryAfter?: number) {
    super(`DevPulse API ${status}: ${problem.title ?? "error"}${problem.detail ? ` - ${problem.detail}` : ""}`);
    this.name = "ApiProblemError";
    this.status = status;
    this.problem = problem;
    this.headers = headers;
    this.retryAfter = retryAfter;
  }
  get type() {
    return this.problem.type;
  }
  get title() {
    return this.problem.title;
  }
  get detail() {
    return this.problem.detail;
  }
  get errors() {
    return this.problem.errors;
  }
  get isRateLimited() {
    return this.status === 429;
  }
  get isPreconditionFailed() {
    return this.status === 412;
  }
}

/** The token endpoint refused the credentials (RFC 6749 error response) or was unreachable. */
export class ApiAuthError extends Error {
  readonly status: number;
  readonly code: string;
  constructor(status: number, code: string, description?: string) {
    super(`DevPulse token request failed: ${code}${description ? ` - ${description}` : ""}`);
    this.name = "ApiAuthError";
    this.status = status;
    this.code = code;
  }
}

export type RateLimitInfo = { limit?: number; remaining?: number; resetSeconds?: number; policy?: string };

export type ApiResponse<T> = {
  status: number;
  data: T;
  headers: Headers;
  etag: string | null;
  /** Parsed IETF RateLimit headers when present. */
  rateLimit: RateLimitInfo;
  /** Absolute URL of the next page (RFC 8288 rel="next"), or null. */
  next: string | null;
};

export type RequestOptions = {
  query?: Record<string, string | number | boolean | undefined | null | (string | number | boolean)[]>;
  body?: unknown;
  headers?: Record<string, string>;
  /** Sends If-Match (use the etag of an earlier read). */
  ifMatch?: string;
  signal?: AbortSignal;
};

export type Page<T> = { items: T[]; nextCursor?: string | null };

const encoder = new TextEncoder();

/** Parse a Retry-After value (delta-seconds or HTTP-date) to seconds. */
export function parseRetryAfter(value: string | null, nowMs = Date.now()): number | undefined {
  if (!value) return undefined;
  const v = value.trim();
  if (/^\d+$/.test(v)) return Number(v);
  const t = Date.parse(v);
  return Number.isNaN(t) ? undefined : Math.max(0, Math.ceil((t - nowMs) / 1000));
}

/** Extract the rel="next" target from an RFC 8288 Link header. */
export function parseNextLink(header: string | null): string | null {
  if (!header) return null;
  for (const m of header.matchAll(/<([^>]*)>\s*((?:;\s*[^;,]+)*)/g)) {
    const params = m[2] ?? "";
    const rel = /;\s*rel\s*=\s*(?:"([^"]*)"|([^\s;,]+))/i.exec(params);
    const rels = (rel?.[1] ?? rel?.[2] ?? "").toLowerCase().split(/\s+/);
    if (rels.includes("next")) return m[1] ?? null;
  }
  return null;
}

function parseRateLimit(h: Headers): RateLimitInfo {
  const out: RateLimitInfo = {};
  const policy = h.get("ratelimit-policy");
  if (policy) out.policy = policy;
  const rl = h.get("ratelimit");
  const num = (re: RegExp, s: string) => {
    const m = re.exec(s);
    return m ? Number(m[1]) : undefined;
  };
  if (rl) {
    out.limit = num(/limit\s*=\s*(\d+)/i, rl);
    out.remaining = num(/remaining\s*=\s*(\d+)/i, rl);
    out.resetSeconds = num(/reset\s*=\s*(\d+)/i, rl);
  }
  const legacy = (n: string) => (h.get(n) !== null && /^\d+$/.test(h.get(n)!) ? Number(h.get(n)) : undefined);
  out.limit ??= legacy("ratelimit-limit");
  out.remaining ??= legacy("ratelimit-remaining");
  out.resetSeconds ??= legacy("ratelimit-reset");
  return out;
}

export class ApiClient {
  readonly host: string;
  private readonly origin: string;
  private readonly o: Required<Pick<ApiClientOptions, "refreshSkewSeconds" | "maxRetries" | "retryBaseMs" | "maxRetryDelayMs" | "timeoutMs">> & ApiClientOptions;
  #token: { value: string; expiresAt: number } | null = null;
  private pending: Promise<string> | null = null;
  readonly #secret: string;

  constructor(options: ApiClientOptions) {
    if (!options.host) throw new Error("host is required");
    if (!options.clientId) throw new Error("clientId is required");
    if (!options.clientSecret) throw new Error("clientSecret is required");
    assertSecureUrl("host", options.host);
    this.host = options.host.replace(/\/+$/, "");
    this.origin = new URL(this.host).origin;
    this.#secret = options.clientSecret;
    const { clientSecret: _drop, ...rest } = options;
    this.o = { refreshSkewSeconds: 60, maxRetries: 3, retryBaseMs: 500, maxRetryDelayMs: 30_000, timeoutMs: 30_000, ...rest, clientSecret: "" };
  }

  /** Never serialize or log credentials. */
  toJSON() {
    return { host: this.host, clientId: this.o.clientId };
  }

  private now() {
    return (this.o.now ?? Date.now)();
  }

  private f(): typeof fetch {
    return this.o.fetch ?? globalThis.fetch;
  }

  private sleep(ms: number) {
    return (this.o.sleep ?? ((n) => new Promise<void>((r) => setTimeout(r, n))))(ms);
  }

  /** A valid access token, fetched with the client credentials grant and cached until shortly before expiry. */
  async getAccessToken(forceRefresh = false): Promise<string> {
    if (!forceRefresh && this.#token && this.now() < this.#token.expiresAt - this.o.refreshSkewSeconds * 1000) return this.#token.value;
    this.pending ??= this.fetchToken().finally(() => (this.pending = null));
    return this.pending;
  }

  /** Forget the cached token (e.g. after revoking it). */
  clearToken() {
    this.#token = null;
  }

  private async fetchToken(): Promise<string> {
    const basic = btoa(String.fromCharCode(...encoder.encode(`${encodeURIComponent(this.o.clientId)}:${encodeURIComponent(this.#secret)}`)));
    const form = new URLSearchParams({ grant_type: "client_credentials" });
    if (this.o.scope) form.set("scope", this.o.scope);
    let res: Response;
    try {
      res = await this.f()(`${this.host}/oauth/token`, {
        method: "POST",
        headers: { authorization: `Basic ${basic}`, "content-type": "application/x-www-form-urlencoded", accept: "application/json" },
        body: form,
        cache: "no-store",
        redirect: "error",
        signal: this.o.timeoutMs ? AbortSignal.timeout(this.o.timeoutMs) : undefined,
      } as RequestInit);
    } catch (err) {
      throw new ApiAuthError(0, "network_error", (err as Error).message);
    }
    const json = (await res.json().catch(() => ({}))) as { access_token?: string; expires_in?: number; error?: string; error_description?: string };
    if (!res.ok || !json.access_token) throw new ApiAuthError(res.status, json.error ?? "invalid_response", json.error_description);
    const ttl = typeof json.expires_in === "number" && json.expires_in > 0 ? json.expires_in : 300;
    this.#token = { value: json.access_token, expiresAt: this.now() + ttl * 1000 };
    return json.access_token;
  }

  private url(path: string, query?: RequestOptions["query"]): string {
    if (!path.startsWith("/") || path.startsWith("//") || /^[a-z][a-z0-9+.-]*:/i.test(path)) throw new Error("path must be a relative path starting with a single /");
    // Reject dot segments (also %2e-encoded, and the \ / tab / newline forms the URL parser rewrites) so an
    // interpolated id such as ".." (encodeURIComponent leaves it alone) cannot climb to another endpoint.
    const pathname = path.split(/[?#]/, 1)[0]!;
    if (/[\\\t\n\r]/.test(pathname) || pathname.split("/").some((s) => /^(?:\.|%2e){1,2}$/i.test(s))) throw new Error("path must not contain . or .. segments");
    const u = new URL(`${this.host}${path}`);
    if (u.origin !== this.origin) throw new Error("path must stay on the configured host");
    for (const [k, v] of Object.entries(query ?? {})) {
      for (const x of Array.isArray(v) ? v : [v]) if (x !== undefined && x !== null) u.searchParams.append(k, String(x));
    }
    return u.toString();
  }

  private delay(attempt: number, retryAfter: number | undefined): number {
    if (retryAfter !== undefined) return Math.min(retryAfter * 1000, this.o.maxRetryDelayMs);
    const exp = this.o.retryBaseMs * 2 ** attempt;
    return Math.min(exp * (0.5 + (this.o.random ?? Math.random)() / 2), this.o.maxRetryDelayMs);
  }

  /** Send a request to a path under /api/v1 (or any same-origin path). Throws ApiProblemError on non-2xx. */
  async request<T = unknown>(method: string, path: string, opts: RequestOptions = {}): Promise<ApiResponse<T>> {
    return this.send<T>(method, this.url(path, opts.query), opts);
  }

  get<T = unknown>(path: string, opts?: Omit<RequestOptions, "body">) {
    return this.request<T>("GET", path, opts);
  }
  post<T = unknown>(path: string, body?: unknown, opts?: Omit<RequestOptions, "body">) {
    return this.request<T>("POST", path, { ...opts, body });
  }
  put<T = unknown>(path: string, body?: unknown, opts?: Omit<RequestOptions, "body">) {
    return this.request<T>("PUT", path, { ...opts, body });
  }
  patch<T = unknown>(path: string, body?: unknown, opts?: Omit<RequestOptions, "body">) {
    return this.request<T>("PATCH", path, { ...opts, body });
  }
  delete<T = unknown>(path: string, opts?: Omit<RequestOptions, "body">) {
    return this.request<T>("DELETE", path, opts);
  }

  /** Iterate list pages by following Link rel="next" (same origin only). Yields each page's body. */
  async *pages<T = unknown>(path: string, opts: Omit<RequestOptions, "body"> = {}): AsyncGenerator<ApiResponse<Page<T>>> {
    let res = await this.get<Page<T>>(path, opts);
    for (;;) {
      yield res;
      if (!res.next) return;
      const next = new URL(res.next, this.host);
      if (next.origin !== this.origin) throw new Error("Refusing to follow a Link header to another origin");
      res = await this.send<Page<T>>("GET", next.toString(), { headers: opts.headers, signal: opts.signal });
    }
  }

  /** Iterate every item across all pages. */
  async *paginate<T = unknown>(path: string, opts: Omit<RequestOptions, "body"> = {}): AsyncGenerator<T> {
    for await (const page of this.pages<T>(path, opts)) yield* page.data?.items ?? [];
  }

  private async send<T>(method: string, url: string, opts: RequestOptions): Promise<ApiResponse<T>> {
    const idempotent = !["POST", "PATCH"].includes(method.toUpperCase());
    let refreshed = false;
    for (let attempt = 0; ; ) {
      const token = await this.getAccessToken();
      const headers: Record<string, string> = { accept: "application/json, application/problem+json", "user-agent": `DevPulseApi/${SDK_VERSION}`, ...opts.headers, authorization: `Bearer ${token}` };
      if (opts.ifMatch) headers["if-match"] = opts.ifMatch;
      let body: string | undefined;
      if (opts.body !== undefined) {
        body = JSON.stringify(opts.body);
        headers["content-type"] ??= "application/json";
      }
      const timeout = this.o.timeoutMs ? AbortSignal.timeout(this.o.timeoutMs) : undefined;
      const signal = opts.signal && timeout ? AbortSignal.any([opts.signal, timeout]) : (opts.signal ?? timeout);
      const res = await this.f()(url, { method, headers, body, signal, redirect: "error" } as RequestInit);
      if (res.ok) return this.parse<T>(res);
      if (res.status === 401 && !refreshed) {
        refreshed = true;
        await res.body?.cancel().catch(() => {});
        this.clearToken();
        await this.getAccessToken(true);
        continue;
      }
      const retryAfter = parseRetryAfter(res.headers.get("retry-after"), this.now());
      const retryable = res.status === 429 || (res.status === 503 && idempotent);
      if (retryable && attempt < this.o.maxRetries) {
        await res.body?.cancel().catch(() => {});
        await this.sleep(this.delay(attempt, retryAfter));
        attempt++;
        continue;
      }
      throw await this.problem(res, retryAfter);
    }
  }

  private async parse<T>(res: Response): Promise<ApiResponse<T>> {
    let data: unknown;
    if (res.status !== 204) {
      const text = await res.text();
      if (text) {
        try {
          data = JSON.parse(text);
        } catch {
          data = text;
        }
      }
    }
    let next: string | null = null;
    const link = parseNextLink(res.headers.get("link"));
    if (link) {
      try {
        const u = new URL(link, this.host);
        if (u.origin === this.origin) next = u.toString();
      } catch {
        /* ignore a malformed link */
      }
    }
    return { status: res.status, data: data as T, headers: res.headers, etag: res.headers.get("etag"), rateLimit: parseRateLimit(res.headers), next };
  }

  private async problem(res: Response, retryAfter: number | undefined): Promise<ApiProblemError> {
    let problem: ProblemDetails = {};
    try {
      const j = JSON.parse(await res.text());
      if (j && typeof j === "object" && !Array.isArray(j)) problem = j as ProblemDetails;
    } catch {
      /* not JSON */
    }
    problem.status ??= res.status;
    problem.title ??= res.statusText || `HTTP ${res.status}`;
    return new ApiProblemError(res.status, problem, res.headers, retryAfter);
  }
}

export function createApiClient(options: ApiClientOptions) {
  return new ApiClient(options);
}
