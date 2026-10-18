import { parseServiceSlugs, resolveConfig, type ResolvedConfig } from "./config.js";
import {
  loadSigningKey,
  loadPublicKey,
  signRequest,
  verifyJwtLease,
  leaseServices,
  maskSecret,
  redactSecrets,
  sha256Base64Url,
  generateDpopKey,
  createDpopProof,
  base64UrlToBytes,
  utf8ToString,
  type DpopKey,
} from "./crypto/index.js";
import {
  DaywalkerAuthError,
  DaywalkerError,
  DaywalkerRateLimitError,
  type DaywalkerConfig,
  type TokenSet,
  type GetTokensOptions,
  type PublicJwk,
  type RateLimitWindow,
  type RetryOptions,
  type SelfCheckResult,
  type SigningKey,
  type TokenPayload,
  type ValidateResult,
} from "./types.js";

function parseRetryAfter(headerValue: string | null): number | undefined {
  if (!headerValue) return undefined;
  const seconds = parseInt(headerValue.trim(), 10);
  if (!Number.isNaN(seconds) && seconds >= 0) {
    return seconds;
  }
  const date = Date.parse(headerValue);
  if (!Number.isNaN(date)) {
    const diff = Math.ceil((date - Date.now()) / 1000);
    return diff > 0 ? diff : 0;
  }
  return undefined;
}

function generateNonce(): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Validation results kept in memory; the least recently used are evicted past this. */
export const MAX_VALIDATION_CACHE_ENTRIES = 1000;

/** Longest 429 `Retry-After` waited out by default (`retry.maxRetryAfterMs`); longer ones return the 429. */
export const MAX_RETRY_AFTER_MS = 60_000;

/** Methods retried after a network error or timeout by default: repeating them can't change server state. */
const IDEMPOTENT_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

export type DaywalkerFetchInit = Omit<RequestInit, "body"> & {
  /**
   * Plain objects and arrays are sent as JSON. Strings, Uint8Array / ArrayBuffer(View) and URLSearchParams
   * are sent (and digested) byte for byte, and Blobs are read into memory first when signing. FormData and
   * ReadableStream bodies can't be digested, so they throw when a signing key is configured.
   */
  body?: BodyInit | object | null;
  retry?: RetryOptions;
  /** Per-attempt timeout overriding `config.timeoutMs`; 0 disables. */
  timeoutMs?: number;
  /** Sent as `Idempotency-Key` (unless already set) and lets non-idempotent requests retry network errors. */
  idempotencyKey?: string;
};

interface PreparedBody {
  /** The exact bytes sent, for Content-Digest; null when there is no body or it can't be read up front. */
  bytes: string | Uint8Array | null;
  send: BodyInit | null;
  contentType?: string;
  /** False for one-shot streams, which can't be sent twice. */
  replayable: boolean;
}

function isPlainJsonValue(value: object): boolean {
  if (Array.isArray(value)) return true;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

async function prepareBody(raw: DaywalkerFetchInit["body"], signing: boolean): Promise<PreparedBody> {
  if (raw === undefined || raw === null) return { bytes: null, send: null, replayable: true };
  if (typeof raw === "string") return { bytes: raw, send: raw, replayable: true };
  if (raw instanceof Uint8Array) return { bytes: raw, send: raw as BodyInit, replayable: true };
  if (raw instanceof ArrayBuffer || ArrayBuffer.isView(raw)) {
    const bytes = raw instanceof ArrayBuffer ? new Uint8Array(raw) : new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength);
    return { bytes, send: bytes as BodyInit, replayable: true };
  }
  if (raw instanceof URLSearchParams) {
    const str = raw.toString();
    return { bytes: str, send: str, contentType: "application/x-www-form-urlencoded;charset=UTF-8", replayable: true };
  }
  if (typeof Blob !== "undefined" && raw instanceof Blob) {
    if (!signing) return { bytes: null, send: raw, replayable: true };
    const bytes = new Uint8Array(await raw.arrayBuffer());
    return { bytes, send: bytes as BodyInit, contentType: raw.type || undefined, replayable: true };
  }
  const isFormData = typeof FormData !== "undefined" && raw instanceof FormData;
  const isStream = typeof ReadableStream !== "undefined" && raw instanceof ReadableStream;
  if (isFormData || isStream) {
    if (signing) {
      throw new DaywalkerError(
        `${isFormData ? "FormData" : "ReadableStream"} bodies can't be signed: their exact bytes aren't known up front, so no Content-Digest can be computed. Serialize the body to a string or Uint8Array first.`
      );
    }
    return { bytes: null, send: raw as BodyInit, replayable: !isStream };
  }
  if (typeof raw === "object" && isPlainJsonValue(raw)) {
    const json = JSON.stringify(raw);
    return { bytes: json, send: json, contentType: "application/json", replayable: true };
  }
  throw new DaywalkerError(
    `Unsupported fetch() body (${Object.prototype.toString.call(raw)}): pass a plain object or array (sent as JSON), a string, Uint8Array, ArrayBuffer, URLSearchParams or Blob`
  );
}

/** Resolves after `ms`, or rejects with the signal's reason as soon as it aborts. */
function sleep(ms: number, signal?: AbortSignal | null): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) return reject(signal.reason);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    signal?.addEventListener("abort", onAbort, { once: true });
  });
}

/**
 * The signal for one attempt: the caller's signal combined with a `timeoutMs` timer, via `AbortSignal.any`
 * (Node >= 20.3) or a manual fallback. `cleanup()` clears the timer once response headers arrive.
 */
function attemptSignal(caller: AbortSignal | null | undefined, timeoutMs: number): { signal?: AbortSignal; cleanup: () => void } {
  const signals: AbortSignal[] = caller ? [caller] : [];
  let timer: ReturnType<typeof setTimeout> | undefined;
  if (timeoutMs > 0) {
    const timeout = new AbortController();
    timer = setTimeout(
      () => timeout.abort(new DOMException(`Request to Daywalker Auth timed out after ${timeoutMs}ms`, "TimeoutError")),
      timeoutMs
    );
    signals.push(timeout.signal);
  }
  const clear = () => clearTimeout(timer);
  if (signals.length <= 1) return { signal: signals[0], cleanup: clear };
  if (typeof AbortSignal.any === "function") return { signal: AbortSignal.any(signals), cleanup: clear };
  const combined = new AbortController();
  const onAbort = (e: Event) => combined.abort((e.target as AbortSignal).reason);
  for (const s of signals) {
    if (s.aborted) combined.abort(s.reason);
    else s.addEventListener("abort", onAbort, { once: true });
  }
  return {
    signal: combined.signal,
    cleanup: () => {
      clear();
      for (const s of signals) s.removeEventListener("abort", onAbort);
    },
  };
}

/** Reads a response body, giving up (and cancelling it) after `timeoutMs` so a trickling body can't hang us. */
async function readText(res: Response, timeoutMs: number): Promise<string> {
  if (!(timeoutMs > 0)) return res.text();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      res.body?.cancel().catch(() => {});
      reject(new DOMException(`Reading the Daywalker Auth response timed out after ${timeoutMs}ms`, "TimeoutError"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([res.text(), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

function isRedirect(res: Response): boolean {
  return res.type === "opaqueredirect" || REDIRECT_STATUSES.has(res.status);
}

function redirectError(what: string, res: Response): DaywalkerError {
  res.body?.cancel().catch(() => {});
  return new DaywalkerError(
    `Daywalker Auth answered ${what} with a redirect (HTTP ${res.status}); refusing to follow it with credentials`,
    res.status || undefined,
    "UNEXPECTED_REDIRECT"
  );
}

/**
 * A failed client credentials grant or refresh as a validation result. Missing configuration is a 500;
 * anything else (invalid_client, access_denied, an outage) is a 503, since it says nothing about the
 * caller's token. Never cached.
 */
function credentialFailure(err: DaywalkerAuthError): ValidateResult {
  if (err.code === "CONFIGURATION_ERROR") {
    return { ok: false, error: "CONFIGURATION_ERROR", status: 500, message: err.message };
  }
  return {
    ok: false,
    error: "SERVICE_UNAVAILABLE",
    status: 503,
    message: redactSecrets(`Could not obtain an OAuth access token${err.code ? ` (${err.code})` : ""}: ${err.message}`),
  };
}

/** The payload of a JWT this client was just issued over TLS; not verified, only read. */
function decodeJwtClaims(jwt: string): Record<string, unknown> {
  try {
    const claims = JSON.parse(utf8ToString(base64UrlToBytes(jwt.split(".")[1] ?? "")));
    return claims && typeof claims === "object" ? claims : {};
  } catch {
    return {};
  }
}

/** The `code` (else `error`) of a JSON error answer, read from a copy so the caller still gets the body. */
async function errorCode(res: Response): Promise<string | undefined> {
  const json = (await res.clone().json().catch(() => null)) as Record<string, unknown> | null;
  const code = json?.code ?? json?.error;
  return typeof code === "string" ? code : undefined;
}

function isRateLimitWindow(value: unknown): value is RateLimitWindow {
  if (!value || typeof value !== "object") return false;
  const w = value as Record<string, unknown>;
  return ["limit", "remaining", "reset"].every((k) => typeof w[k] === "number" && Number.isFinite(w[k]));
}

/** Why a `valid: true` answer can't be trusted as a validation result, or null when its shape is sane. */
function malformedValidation(json: Record<string, unknown>, payloadData: Record<string, unknown>): string | null {
  for (const src of [json, payloadData]) {
    for (const k of ["serviceSlug", "tenantId", "tokenId", "tokenName", "userId", "stage"]) {
      if (src[k] !== undefined && src[k] !== null && typeof src[k] !== "string") return `${k} is not a string`;
    }
    if (src.services !== undefined && src.services !== null && !(Array.isArray(src.services) && src.services.every((s) => typeof s === "string"))) {
      return "services is not a list of strings";
    }
    for (const k of ["rateLimit", "rateLimitHourly"]) {
      if (src[k] !== undefined && src[k] !== null && !isRateLimitWindow(src[k])) return `${k} is not a rate limit window`;
    }
  }
  return null;
}

/** Results are handed out as copies, so a caller mutating one can't alter what other callers get from the cache. */
function cloneResult(result: ValidateResult): ValidateResult {
  return typeof structuredClone === "function" ? structuredClone(result) : (JSON.parse(JSON.stringify(result)) as ValidateResult);
}

const DEFAULT_ISSUER = "https://auth.daywalker.dev";
const TOKEN_PATH = "/api/v1/oauth/token";

export class Daywalker {
  private readonly _config: ResolvedConfig;
  private readonly _rawConfig: DaywalkerConfig;
  private _signingKeyPromise?: Promise<SigningKey>;
  private _previousSigningKeyPromise?: Promise<SigningKey>;
  private readonly _cache = new Map<string, { result: ValidateResult; expiresAt: number }>();
  private readonly _inflight = new Map<string, Promise<ValidateResult>>();

  constructor(config: DaywalkerConfig = {}) {
    this._rawConfig = config;
    this._config = resolveConfig(config);
  }

  public get config(): ResolvedConfig {
    return this._config;
  }

  public toJSON(): Record<string, unknown> {
    return {
      serviceSlug: this._config.serviceSlug,
      domain: this._config.domain,
      authUrl: this._config.authUrl,
      keyId: this._config.keyId,
      apiKey: maskSecret(this._config.apiKey),
      signingKey: this._config.signingKey ? "[configured]" : null,
      daywalkerPublicKey: this._config.daywalkerPublicKey ? "[configured]" : null,
    };
  }

  // Node.js custom inspect masking
  public [Symbol.for("nodejs.util.inspect.custom")](): Record<string, unknown> {
    return this.toJSON();
  }

  private async getLoadedSigningKey(): Promise<SigningKey | null> {
    if (!this._config.signingKey) return null;
    if (typeof this._config.signingKey !== "string" && "privateKey" in this._config.signingKey) {
      return this._config.signingKey;
    }
    if (!this._signingKeyPromise) {
      this._signingKeyPromise = loadSigningKey(this._config.signingKey as string);
    }
    return this._signingKeyPromise;
  }

  private _dpopKey: Promise<DpopKey> | null = null;

  /** The client's DPoP key, generated on first use. Issued tokens are bound to it for this client's life. */
  private getDpopKey(): Promise<DpopKey> {
    return (this._dpopKey ??= generateDpopKey());
  }

  private async getLoadedPreviousSigningKey(): Promise<SigningKey | null> {
    const raw = this._config.previousSigningKey;
    if (!raw) return null;
    if (!this._previousSigningKeyPromise) {
      this._previousSigningKeyPromise = loadSigningKey(raw);
    }
    return this._previousSigningKeyPromise;
  }

  /**
   * Signs and executes a request to Daywalker Auth (same origin as `authUrl` only).
   * - Redirects are never followed: a 3xx throws a DaywalkerError (code UNEXPECTED_REDIRECT), so the API key,
   *   signature and body never reach another URL and no redirect target's answer is trusted.
   * - Each attempt times out after `timeoutMs` (default 5000ms) of waiting for response headers; the caller's
   *   `signal` aborts immediately, including during backoff, and is never retried.
   * - 429s are retried with exponential backoff, honoring `Retry-After` up to `retry.maxRetryAfterMs`. Network
   *   errors and timeouts are retried only for GET / HEAD / OPTIONS, with an `idempotencyKey`, or when
   *   `retry.retryNetworkErrors` is true. Options merge as defaults < `config.retry` < `init.retry`.
   * - An explicit `Authorization` header is sent as given; otherwise `DPoP <access token>` from the OAuth
   *   client credentials flow (`accessToken()`) is added, with a DPoP proof bound to it. The API key is never
   *   sent here: it only authenticates the client credentials grant. An answer of 401 ACCESS_TOKEN_EXPIRED
   *   refreshes the token and retries once. The signature covers method, path, query, authority and
   *   Content-Digest, never Authorization.
   */
  public async fetch(
    path: string,
    init?: DaywalkerFetchInit
  ): Promise<Response> {
    const authUrl = this._config.authUrl;
    const url = new URL(path, authUrl);
    // Absolute URLs to other hosts would otherwise receive an access token and a valid signature.
    const authOrigin = new URL(authUrl).origin;
    if (url.origin !== authOrigin) {
      throw new DaywalkerError(`Refusing to send Daywalker credentials to ${url.origin}; fetch() only targets ${authOrigin}`);
    }
    const method = (init?.method ?? (init?.body !== undefined ? "POST" : "GET")).toUpperCase();
    const doFetch = this._rawConfig.fetch ?? globalThis.fetch;
    const { retry: _retry, timeoutMs: _timeoutMs, idempotencyKey, body: rawBody, signal: callerSignal, ...requestInit } = init ?? {};

    const retryOpts: RetryOptions = { ...this._config.retry };
    for (const [k, v] of Object.entries(init?.retry ?? {})) {
      if (v !== undefined) (retryOpts as Record<string, unknown>)[k] = v;
    }
    const maxRetries = retryOpts.maxRetries ?? 3;
    const initialDelayMs = retryOpts.initialDelayMs ?? 500;
    const maxDelayMs = retryOpts.maxDelayMs ?? 30_000;
    const backoffFactor = retryOpts.backoffFactor ?? 2;
    const jitter = retryOpts.jitter ?? true;
    const maxRetryAfterMs = retryOpts.maxRetryAfterMs ?? MAX_RETRY_AFTER_MS;
    const retryNetworkErrors = retryOpts.retryNetworkErrors ?? (IDEMPOTENT_METHODS.has(method) || Boolean(idempotencyKey));
    const timeoutMs = init?.timeoutMs ?? this._config.timeoutMs;
    const backoff = (n: number) => {
      let delayMs = initialDelayMs * Math.pow(backoffFactor, n - 1);
      if (jitter) delayMs = delayMs * (0.8 + Math.random() * 0.4);
      return Math.min(delayMs, maxDelayMs);
    };

    callerSignal?.throwIfAborted();
    const signingKey = await this.getLoadedSigningKey();
    const body = await prepareBody(rawBody, Boolean(signingKey));
    // The token endpoint authenticates itself (see _tokenRequest); everything else gets an OAuth access token.
    const isTokenEndpoint = url.pathname === TOKEN_PATH;
    const autoAuth = !isTokenEndpoint && !new Headers(init?.headers).has("authorization");
    let refreshedExpired = false;

    let attempt = 0;
    while (true) {
      callerSignal?.throwIfAborted();
      const headers = new Headers(init?.headers);

      if (body.contentType && !headers.has("content-type")) {
        headers.set("content-type", body.contentType);
      }
      if (!headers.has("accept")) {
        headers.set("accept", "application/json");
      }
      if (autoAuth) {
        headers.set("authorization", `DPoP ${await this.accessToken()}`);
      }
      if (idempotencyKey && !headers.has("idempotency-key")) {
        headers.set("idempotency-key", idempotencyKey);
      }
      // DPoP (RFC 9449) is mandatory on the token endpoint and when presenting a DPoP access token.
      const auth = headers.get("authorization") ?? "";
      const isDpopAuth = /^dpop\s+/i.test(auth);
      if ((autoAuth || !headers.has("dpop")) && (isTokenEndpoint || isDpopAuth)) {
        const accessToken = isDpopAuth ? auth.replace(/^dpop\s+/i, "") : undefined;
        headers.set("dpop", await createDpopProof(await this.getDpopKey(), { method, url: url.toString(), accessToken }));
      }

      if (signingKey) {
        // apiKey is left out so the signer can't replace an explicit Authorization header.
        const signedHeaders = await signRequest({
          method,
          path: url.pathname + url.search,
          authority: url.host,
          body: body.bytes,
          key: signingKey,
          keyid: this._config.keyId ?? undefined,
          nonce: generateNonce(),
        });

        for (const [k, v] of Object.entries(signedHeaders)) {
          if (v !== undefined) {
            headers.set(k, v);
          }
        }
      }

      const { signal, cleanup } = attemptSignal(callerSignal, timeoutMs);
      const reqInit: RequestInit = {
        ...requestInit,
        method,
        headers,
        body: body.send ?? undefined,
        redirect: requestInit.redirect === "error" ? "error" : "manual",
        signal,
      };

      let res: Response;
      try {
        res = await doFetch(url.toString(), reqInit);
      } catch (err) {
        if (callerSignal?.aborted) throw err;
        if (retryNetworkErrors && body.replayable && attempt < maxRetries) {
          attempt++;
          await sleep(backoff(attempt), callerSignal);
          continue;
        }
        throw err;
      } finally {
        cleanup();
      }

      if (isRedirect(res)) {
        throw redirectError(url.pathname, res);
      }

      if (res.status === 401 && autoAuth && !refreshedExpired && body.replayable && (await errorCode(res)) === "ACCESS_TOKEN_EXPIRED") {
        // The server's clock says the token expired before ours did: refresh it and try once more.
        refreshedExpired = true;
        if (this._tokens) this._tokens = { ...this._tokens, expiresAt: 0 };
        res.body?.cancel().catch(() => {});
        continue;
      }

      if (res.status === 429 && body.replayable && attempt < maxRetries) {
        const retryAfterSec = parseRetryAfter(res.headers.get("retry-after"));
        let delayMs = backoff(attempt + 1);
        if (retryAfterSec !== undefined) {
          // Retrying sooner than the server asked is pointless; waiting longer than this is the caller's call.
          if (retryAfterSec * 1000 > maxRetryAfterMs) return res;
          delayMs = Math.max(delayMs, retryAfterSec * 1000);
        }
        attempt++;
        res.body?.cancel().catch(() => {});
        await sleep(delayMs, callerSignal);
        continue;
      }

      return res;
    }
  }

  private _cacheGet(key: string): ValidateResult | undefined {
    const entry = this._cache.get(key);
    if (!entry) return undefined;
    this._cache.delete(key);
    if (entry.expiresAt <= Date.now()) return undefined;
    this._cache.set(key, entry); // most recently used goes last
    return entry.result;
  }

  private _cacheSet(key: string, result: ValidateResult, ttlMs: number, notAfterMs = Infinity): void {
    const expiresAt = Math.min(Date.now() + ttlMs, notAfterMs);
    if (expiresAt <= Date.now()) return;
    this._cache.delete(key);
    this._cache.set(key, { result, expiresAt });
    while (this._cache.size > MAX_VALIDATION_CACHE_ENTRIES) {
      this._cache.delete(this._cache.keys().next().value as string);
    }
  }

  /**
   * Validates an incoming bearer token with memory caching and discriminated union return.
   * Supports zero-egress offline verification for JWT token leases when Daywalker's public key is configured.
   * A missing token is always rejected (401); it never falls back to this service's own API key —
   * use `validateServiceKey()` for that.
   * Online validation fails closed: only a 2xx JSON answer with `valid: true` and a sane shape is accepted.
   * Outages (network errors, timeouts, 5xx, malformed answers) return status 503 with error NETWORK_ERROR or
   * SERVICE_UNAVAILABLE and are never cached. Each call gets its own copy of the (cached) result.
   */
  public async validateToken(
    tokenOrOptions?: string | { token?: string; serviceSlug?: string; forceRefresh?: boolean; offlineOnly?: boolean },
    options?: { serviceSlug?: string; forceRefresh?: boolean; offlineOnly?: boolean }
  ): Promise<ValidateResult> {
    let token: string | undefined;
    let serviceSlug: string;
    let forceRefresh = false;
    let offlineOnly = false;

    if (typeof tokenOrOptions === "string") {
      token = tokenOrOptions;
      serviceSlug = (options?.serviceSlug ?? this._config.serviceSlug ?? "").toLowerCase();
      forceRefresh = options?.forceRefresh ?? false;
      offlineOnly = options?.offlineOnly ?? false;
    } else {
      token = tokenOrOptions?.token ?? undefined;
      serviceSlug = (tokenOrOptions?.serviceSlug ?? this._config.serviceSlug ?? "").toLowerCase();
      forceRefresh = tokenOrOptions?.forceRefresh ?? false;
      offlineOnly = tokenOrOptions?.offlineOnly ?? false;
    }

    if (!token) {
      return {
        ok: false,
        error: "INVALID_TOKEN",
        status: 401,
        message: "Missing token to validate",
      };
    }

    // Keyed by a hash so raw tokens are never held as cache keys.
    const cacheKey = `${serviceSlug || "default"}:${await sha256Base64Url(token)}`;
    const cached = forceRefresh ? undefined : this._cacheGet(cacheKey);
    if (cached) {
      return cloneResult(cached);
    }

    // Check for offline JWT lease verification
    if (this._config.daywalkerPublicKey && token.split(".").length === 3) {
      const jwtResult = await verifyJwtLease({
        token,
        publicKey: this._config.daywalkerPublicKey,
        expectedServiceSlug: serviceSlug || undefined,
        expectedIssuer: this._config.leaseIssuer ?? DEFAULT_ISSUER,
      });

      if (jwtResult.valid && jwtResult.payload) {
        const payload = jwtResult.payload;
        const result: ValidateResult = {
          ok: true,
          data: {
            serviceSlug: serviceSlug || ((payload.serviceSlug || payload.service || "") as string),
            tenantId: (payload.tenantId || payload.sub || "") as string,
            rateLimit: (payload.rateLimit as RateLimitWindow) ?? {
              limit: 1000,
              remaining: 999,
              reset: Math.floor(Date.now() / 1000) + 60,
            },
            rateLimitHourly: payload.rateLimitHourly as RateLimitWindow | undefined,
            tokenId: (payload.tokenId || payload.sub) as string | undefined,
            tokenName: payload.tokenName as string | undefined,
            userId: payload.userId as string | undefined,
            stage: payload.stage as string | undefined,
            offlineVerified: true,
            ...payload,
            // Every service the lease covers: its `services` claim, else its audience.
            services: leaseServices(payload),
          },
        };

        if (this._config.cacheTtlMs > 0) {
          // Never cache a lease past its own expiry.
          this._cacheSet(cacheKey, result, this._config.cacheTtlMs, (payload.exp as number) * 1000);
        }
        return cloneResult(result);
      } else if (offlineOnly) {
        return {
          ok: false,
          error: "INVALID_TOKEN",
          status: 401,
          message: jwtResult.error ?? "Offline token verification failed",
        };
      }
    } else if (offlineOnly) {
      return {
        ok: false,
        error: "CONFIGURATION_ERROR",
        status: 500,
        message: "Offline verification requires DAYWALKER_PUBLIC_KEY and a valid JWT token lease",
      };
    }

    // Online verification, deduplicated across concurrent callers
    const inflightKey = `${cacheKey}`;
    const pending = this._inflight.get(inflightKey);
    if (pending) return pending.then(cloneResult);
    const run = this._validateOnline(token, serviceSlug, cacheKey).finally(() => {
      this._inflight.delete(inflightKey);
    });
    this._inflight.set(inflightKey, run);
    return run.then(cloneResult);
  }

  private async _validateOnline(token: string, serviceSlug: string, cacheKey: string): Promise<ValidateResult> {
    const negTtl = this._config.negativeCacheTtlMs;
    const fail = (result: Extract<ValidateResult, { ok: false }>): ValidateResult => {
      if (negTtl > 0 && result.error !== "RATE_LIMITED" && result.error !== "NETWORK_ERROR" && result.error !== "SERVICE_UNAVAILABLE") {
        this._cacheSet(cacheKey, result, negTtl);
      }
      return result;
    };
    // Says nothing about the token, so never cached.
    const unavailable = (message: string): ValidateResult => ({
      ok: false,
      error: "SERVICE_UNAVAILABLE",
      status: 503,
      message: redactSecrets(message),
    });
    try {
      // No service slug is sent: the caller is identified by its credentials, not by naming a service
      const validateBody: Record<string, string> = { token };

      const res = await this.fetch("/api/v1/tokens/validate", {
        method: "POST",
        body: validateBody,
        // Validation is read-only, so repeating it after a lost response is safe.
        retry: { retryNetworkErrors: this._config.retry.retryNetworkErrors ?? true },
      });

      // A body that times out is an outage (thrown to NETWORK_ERROR below), never an empty answer.
      const text = await readText(res, this._config.timeoutMs);
      let parsed: unknown;
      try {
        parsed = JSON.parse(text);
      } catch {
        parsed = undefined;
      }
      const json = (parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {}) as Record<string, unknown>;
      const isObject = json === parsed;

      if (res.status === 429) {
        const retryAfter = parseRetryAfter(res.headers.get("retry-after")) ?? (typeof json.retryAfter === "number" ? json.retryAfter : undefined);
        return {
          ok: false,
          error: "RATE_LIMITED",
          status: 429,
          message: redactSecrets((typeof json.message === "string" && json.message) || "Rate limit exceeded"),
          retryAfter,
        };
      }

      if (res.status >= 500) {
        return unavailable(`Daywalker Auth is unavailable (HTTP ${res.status})`);
      }

      if (res.ok && isObject && json.valid === true) {
        const payloadData = (json.data === undefined ? json : json.data) as Record<string, unknown>;
        if (!payloadData || typeof payloadData !== "object" || Array.isArray(payloadData)) {
          return unavailable("Daywalker Auth returned a malformed validation result (data is not an object)");
        }
        const problem = malformedValidation(json, payloadData);
        if (problem) {
          return unavailable(`Daywalker Auth returned a malformed validation result (${problem})`);
        }
        const data: TokenPayload = {
          serviceSlug: (json.serviceSlug as string) || serviceSlug,
          tenantId: (payloadData.tenantId || payloadData.userId || json.tenantId || json.userId || "") as string,
          rateLimit: (payloadData.rateLimit || json.rateLimit || { limit: 0, remaining: 0, reset: 0 }) as RateLimitWindow,
          rateLimitHourly: (payloadData.rateLimitHourly || json.rateLimitHourly) as RateLimitWindow | undefined,
          tokenId: (payloadData.tokenId || json.tokenId) as string | undefined,
          tokenName: (payloadData.tokenName || json.tokenName) as string | undefined,
          userId: (payloadData.userId || json.userId) as string | undefined,
          stage: (payloadData.stage || json.stage) as string | undefined,
          ...payloadData,
          services: ((payloadData.services ?? json.services) as string[] | undefined) ?? [(json.serviceSlug as string) || serviceSlug],
        };

        const result: ValidateResult = {
          ok: true,
          data,
        };

        if (this._config.cacheTtlMs > 0) {
          this._cacheSet(cacheKey, result, this._config.cacheTtlMs);
        }
        return result;
      }

      // A 2xx is only a token verdict when it says so; anything else (HTML, `{}`, a captive portal) fails closed.
      if (res.ok && !(isObject && (json.valid === false || typeof json.error === "string"))) {
        return unavailable(`Daywalker Auth returned no validation result (HTTP ${res.status})`);
      }

      let error = "INVALID_TOKEN";
      const errMsg = String((typeof json.message === "string" && json.message) || (typeof json.error === "string" && json.error) || "");
      if (json.error === "EXPIRED" || /expired/i.test(errMsg)) {
        error = "EXPIRED";
      } else if (json.error === "REVOKED" || /revoked/i.test(errMsg)) {
        error = "REVOKED";
      }

      return fail({
        ok: false,
        error,
        // `{ valid: false }` may come with a 200; never hand adapters a success status for a rejection.
        status: res.ok ? 401 : res.status,
        message: redactSecrets(errMsg || `Validation failed with HTTP ${res.status}`),
      });
    } catch (err) {
      // This service couldn't get its own access token: says nothing about the caller's token.
      if (err instanceof DaywalkerAuthError) return credentialFailure(err);
      return {
        ok: false,
        error: "NETWORK_ERROR",
        status: 503,
        message: redactSecrets(`Could not reach Daywalker Auth: ${(err as Error).message}`),
      };
    }
  }

  /**
   * Service health check: runs this service's OAuth client credentials flow (`accessToken()`) and checks
   * that the granted services include `serviceSlug` (default: the configured one). Never use this to
   * authenticate an incoming request. `forceRefresh` starts a new client credentials grant.
   */
  public async validateServiceCredentials(options?: { serviceSlug?: string; forceRefresh?: boolean }): Promise<ValidateResult> {
    const serviceSlug = (options?.serviceSlug ?? this._config.serviceSlug ?? "").toLowerCase();
    let tokens: TokenSet;
    try {
      if (options?.forceRefresh) await this.getTokens();
      else await this.accessToken();
      tokens = this._tokens!;
    } catch (err) {
      if (err instanceof DaywalkerAuthError) return credentialFailure(err);
      return {
        ok: false,
        error: "NETWORK_ERROR",
        status: 503,
        message: redactSecrets(`Could not reach Daywalker Auth: ${(err as Error).message}`),
      };
    }
    if (serviceSlug && tokens.services.length > 0 && !tokens.services.includes(serviceSlug)) {
      return {
        ok: false,
        error: "SERVICE_NOT_GRANTED",
        status: 403,
        message: `The OAuth client credentials don't cover ${serviceSlug} (granted: ${tokens.services.join(", ")})`,
      };
    }
    const claims = decodeJwtClaims(tokens.accessToken);
    const user = claims.user && typeof claims.user === "object" ? (claims.user as Record<string, unknown>) : {};
    const userId = typeof user.id === "string" ? user.id : typeof claims.sub === "string" ? claims.sub : undefined;
    return {
      ok: true,
      data: {
        serviceSlug: serviceSlug || tokens.services[0] || "",
        tenantId: userId ?? "",
        userId,
        rateLimit: { limit: 0, remaining: 0, reset: 0 },
        services: tokens.services,
        expiresAt: tokens.expiresAt,
      },
    };
  }

  /** @deprecated Renamed to `validateServiceCredentials()`; the API key itself is no longer validated. */
  public async validateServiceKey(options?: { serviceSlug?: string; forceRefresh?: boolean }): Promise<ValidateResult> {
    return this.validateServiceCredentials(options);
  }

  /**
   * Throws DaywalkerAuthError or DaywalkerRateLimitError if token is invalid or rate limited.
   */
  public async requireValidToken(
    tokenOrOptions?: string | { token?: string; serviceSlug?: string; offlineOnly?: boolean },
    options?: { serviceSlug?: string; offlineOnly?: boolean }
  ): Promise<TokenPayload> {
    const result = await this.validateToken(tokenOrOptions as any, options);
    if (!result.ok) {
      if (result.status === 429) {
        throw new DaywalkerRateLimitError(result.message, result.retryAfter);
      }
      throw new DaywalkerAuthError(result.message, result.status, result.error);
    }
    return result.data;
  }

  private _tokens: TokenSet | null = null;
  private _tokenFlight: Promise<TokenSet> | null = null;

  /**
   * POST /api/v1/oauth/token. The client credentials grant is the one request that carries the API key
   * (`Authorization: Bearer`, next to the RFC 9421 signature); a refresh is authenticated by its refresh
   * token and DPoP proof alone.
   */
  private async _tokenRequest(body: Record<string, unknown>): Promise<TokenSet> {
    const headers: Record<string, string> = {};
    if (body.grant_type === "client_credentials") {
      if (!this._config.apiKey) {
        throw new DaywalkerAuthError("DAYWALKER_API_KEY is not set: it is the client credential for the OAuth token endpoint", 500, "CONFIGURATION_ERROR");
      }
      headers.authorization = `Bearer ${this._config.apiKey}`;
    }
    const res = await this.fetch(TOKEN_PATH, { method: "POST", body, headers });
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (res.status !== 200) {
      throw new DaywalkerAuthError(
        redactSecrets(String(json.message || json.error || `Token request failed with HTTP ${res.status}`)),
        res.status,
        (json.code as string | undefined) ?? (json.error as string | undefined)
      );
    }
    if (typeof json.access_token !== "string" || typeof json.refresh_token !== "string") {
      throw new DaywalkerAuthError("Daywalker Auth returned a malformed token response", res.status, "SERVICE_UNAVAILABLE");
    }
    const services = Array.isArray(json.services) ? json.services.filter((x): x is string => typeof x === "string") : [];
    return {
      accessToken: json.access_token,
      refreshToken: json.refresh_token,
      tokenType: String(json.token_type ?? "DPoP"),
      expiresAt: Number(json.expires_at) || Math.floor(Date.now() / 1000) + Number(json.expires_in ?? 0),
      expiresIn: Number(json.expires_in ?? 0),
      refreshExpiresIn: Number(json.refresh_expires_in ?? 0),
      scope: String(json.scope ?? services.join(" ")),
      services,
      jwksUri: typeof json.jwks_uri === "string" ? json.jwks_uri : undefined,
    };
  }

  /**
   * Client credentials grant (RFC 6749 §4.4): the signed request (API key + registered Ed25519 key) is
   * exchanged for a short-lived access token JWT listing every service the credentials cover, and a
   * rotating refresh token. No service slug is sent. The tokens are remembered for `accessToken()`.
   */
  public async getTokens(options: GetTokensOptions = {}): Promise<TokenSet> {
    const scope = options.scope ? parseServiceSlugs(options.scope) : undefined;
    if (options.scope && (!scope || scope.length === 0)) {
      throw new DaywalkerAuthError("getTokens: scope must list at least one service slug", 400, "INVALID_REQUEST");
    }
    const tokens = await this._tokenRequest({
      grant_type: "client_credentials",
      ...(scope ? { scope: scope.join(" ") } : {}),
      ...(options.expiresIn ? { expires_in: options.expiresIn } : {}),
    });
    this._tokens = tokens;
    return tokens;
  }

  /**
   * Refresh token rotation: trades the refresh token for a NEW access token and a NEW refresh token; the
   * old refresh token stops working. Presenting an old one again revokes the whole session, so refreshes
   * are serialized per client and the new refresh token must replace the stored one.
   */
  public async refreshTokens(refreshToken?: string): Promise<TokenSet> {
    const token = refreshToken ?? this._tokens?.refreshToken;
    if (!token) throw new DaywalkerAuthError("refreshTokens: no refresh token (call getTokens() first)", 400, "INVALID_REQUEST");
    const tokens = await this._tokenRequest({ grant_type: "refresh_token", refresh_token: token });
    this._tokens = tokens;
    return tokens;
  }

  /**
   * A valid access token, refreshing (or re-authenticating with the client credentials once the session
   * ended) when it is within 30 seconds of expiry. Concurrent callers share one request, so the single-use
   * refresh token is never presented twice.
   */
  public async accessToken(): Promise<string> {
    const current = this._tokens;
    if (current && current.expiresAt - 30 > Math.floor(Date.now() / 1000)) return current.accessToken;
    if (!this._tokenFlight) {
      this._tokenFlight = (async () => {
        if (current) {
          try {
            return await this.refreshTokens();
          } catch (err) {
            if (!(err instanceof DaywalkerAuthError) || err.status !== 400) throw err;
            // invalid_grant: the session ended or was revoked; start a new one
          }
        }
        return this.getTokens();
      })().finally(() => {
        this._tokenFlight = null;
      });
    }
    return (await this._tokenFlight).accessToken;
  }

  /**
   * Fetches Daywalker's public JWKS (GET /.well-known/jwks.json) for offline lease verification.
   * Uses the configured `fetch`, sends no credentials, never follows redirects and times out after `timeoutMs`.
   */
  public async fetchJwks(): Promise<{ keys: PublicJwk[] }> {
    const doFetch = this._rawConfig.fetch ?? globalThis.fetch;
    const { signal, cleanup } = attemptSignal(undefined, this._config.timeoutMs);
    let res: Response;
    try {
      res = await doFetch(`${this._config.authUrl.replace(/\/+$/, "")}/.well-known/jwks.json`, {
        headers: { Accept: "application/json" },
        redirect: "manual",
        signal,
      });
    } finally {
      cleanup();
    }
    if (isRedirect(res)) throw redirectError("/.well-known/jwks.json", res);
    if (!res.ok) throw new DaywalkerError(`Could not fetch JWKS (HTTP ${res.status})`, res.status);
    let json: { keys?: unknown } | null = null;
    try {
      json = JSON.parse(await readText(res, this._config.timeoutMs));
    } catch (err) {
      if ((err as Error).name === "TimeoutError") throw err;
    }
    if (!json || typeof json !== "object" || !Array.isArray(json.keys)) {
      throw new DaywalkerError("JWKS response is not a JWK Set");
    }
    return { keys: json.keys as PublicJwk[] };
  }

  /**
   * The public JWK(s) configured for this service: the current signing key, then the previous one
   * (`previousSigningKey`) during a rotation, so requests from instances still on the old key keep verifying.
   */
  public async keys(): Promise<{ keys: PublicJwk[] }> {
    const key = await this.getLoadedSigningKey();
    const keys = key ? [key.publicJwk] : [];
    // A broken previous key must not take the current one offline; selfCheck() reports it.
    const previous = await this.getLoadedPreviousSigningKey().catch(() => null);
    if (previous && !keys.some((k) => k.kid === previous.publicJwk.kid)) {
      keys.push(previous.publicJwk);
    }
    return { keys };
  }

  /**
   * Check configuration and verify signature readiness.
   */
  public async selfCheck(): Promise<SelfCheckResult> {
    const problems = [...this._config.problems];
    const signingKey = await this.getLoadedSigningKey().catch((err) => {
      problems.push(`Signing key load error: ${(err as Error).message}`);
      return null;
    });

    if (!signingKey) {
      problems.push("DAYWALKER_SIGNING_KEY is not set: requests will be sent without RFC 9421 signature");
    }
    await this.getLoadedPreviousSigningKey().catch((err) => {
      problems.push(`Previous signing key load error: ${(err as Error).message}`);
    });

    const keyId = signingKey?.publicJwk.kid ?? null;
    const offlineVerificationReady = Boolean(this._config.daywalkerPublicKey);

    return {
      ok: problems.length === 0,
      serviceSlug: this._config.serviceSlug,
      serviceSlugs: this._config.serviceSlugs,
      domain: this._config.domain,
      signing: Boolean(signingKey),
      keyId,
      offlineVerificationReady,
      problems,
    };
  }
}

/**
 * Factory function for creating instantiable Daywalker client instances.
 */
export function createDaywalker(config?: DaywalkerConfig): Daywalker {
  return new Daywalker(config);
}

// Retain lazy default client instance for plug-and-play simplicity,
// callable as `daywalker()` or usable directly as `daywalker.fetch(...)`.
let defaultInstance: Daywalker | null = null;
function getDefaultInstance(): Daywalker {
  if (!defaultInstance) {
    defaultInstance = new Daywalker();
  }
  return defaultInstance;
}

export const daywalker: Daywalker & (() => Daywalker) = new Proxy(
  (() => getDefaultInstance()) as any,
  {
    get(_target, prop) {
      const instance = getDefaultInstance();
      const val = (instance as any)[prop];
      if (typeof val === "function") {
        return val.bind(instance);
      }
      return val;
    },
    apply(_target, _thisArg, args) {
      if (args.length > 0) {
        return new Daywalker(args[0]);
      }
      return getDefaultInstance();
    },
  }
);
