import { resolveConfig, type ResolvedConfig } from "./config.js";
import {
  loadSigningKey,
  loadPublicKey,
  signRequest,
  verifyJwtLease,
  maskSecret,
  redactSecrets,
  sha256Base64Url,
} from "./crypto/index.js";
import {
  DaywalkerAuthError,
  DaywalkerError,
  DaywalkerRateLimitError,
  type DaywalkerConfig,
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

export type DaywalkerFetchInit = Omit<RequestInit, "body"> & {
  body?: BodyInit | object | null;
  retry?: RetryOptions;
};

export class Daywalker {
  private readonly _config: ResolvedConfig;
  private readonly _rawConfig: DaywalkerConfig;
  private _signingKeyPromise?: Promise<SigningKey>;
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

  /**
   * Signs and executes requests with automatic retry and exponential backoff on 429 responses.
   */
  public async fetch(
    path: string,
    init?: DaywalkerFetchInit
  ): Promise<Response> {
    const authUrl = this._config.authUrl;
    const url = new URL(path, authUrl);
    // Absolute URLs to other hosts would otherwise receive the API key and a valid signature.
    const authOrigin = new URL(authUrl).origin;
    if (url.origin !== authOrigin) {
      throw new DaywalkerError(`Refusing to send Daywalker credentials to ${url.origin}; fetch() only targets ${authOrigin}`);
    }
    const method = (init?.method ?? (init?.body !== undefined ? "POST" : "GET")).toUpperCase();
    const doFetch = this._rawConfig.fetch ?? globalThis.fetch;

    const retryOpts: RetryOptions = {
      maxRetries: init?.retry?.maxRetries ?? this._config.maxRetries ?? 3,
      initialDelayMs: init?.retry?.initialDelayMs ?? 500,
      maxDelayMs: init?.retry?.maxDelayMs ?? 30_000,
      backoffFactor: init?.retry?.backoffFactor ?? 2,
      jitter: init?.retry?.jitter ?? true,
      ...init?.retry,
    };

    const rawBody = init?.body;
    let bodyString: string | Uint8Array | null = null;
    if (rawBody !== undefined && rawBody !== null) {
      if (typeof rawBody === "string") {
        bodyString = rawBody;
      } else if (rawBody instanceof Uint8Array) {
        bodyString = rawBody;
      } else if (typeof rawBody === "object") {
        bodyString = JSON.stringify(rawBody);
      }
    }

    const signingKey = await this.getLoadedSigningKey();

    let attempt = 0;
    while (true) {
      const headers = new Headers(init?.headers);

      if (rawBody !== undefined && !headers.has("content-type") && typeof rawBody === "object" && !(rawBody instanceof Uint8Array)) {
        headers.set("content-type", "application/json");
      }
      if (!headers.has("accept")) {
        headers.set("accept", "application/json");
      }
      if (this._config.apiKey && !headers.has("authorization")) {
        headers.set("authorization", `Bearer ${this._config.apiKey}`);
      }

      if (signingKey) {
        const signedHeaders = await signRequest({
          method,
          path: url.pathname,
          authority: url.host,
          body: bodyString,
          key: signingKey,
          keyid: this._config.keyId ?? undefined,
          apiKey: this._config.apiKey ?? undefined,
          nonce: generateNonce(),
        });

        for (const [k, v] of Object.entries(signedHeaders)) {
          if (v !== undefined) {
            headers.set(k, v);
          }
        }
      }

      const reqInit: RequestInit = {
        ...init,
        method,
        headers,
        body: (bodyString as BodyInit | null) ?? undefined,
      };

      let res: Response;
      try {
        res = await doFetch(url.toString(), reqInit);
      } catch (err) {
        if (attempt < (retryOpts.maxRetries ?? 3)) {
          attempt++;
          const delay = (retryOpts.initialDelayMs ?? 500) * Math.pow(retryOpts.backoffFactor ?? 2, attempt - 1);
          await new Promise((r) => setTimeout(r, delay));
          continue;
        }
        throw err;
      }

      if (res.status === 429 && attempt < (retryOpts.maxRetries ?? 3)) {
        attempt++;
        const retryAfterSec = parseRetryAfter(res.headers.get("retry-after"));
        let delayMs = (retryOpts.initialDelayMs ?? 500) * Math.pow(retryOpts.backoffFactor ?? 2, attempt - 1);

        if (retryOpts.jitter) {
          delayMs = delayMs * (0.8 + Math.random() * 0.4);
        }

        if (retryAfterSec !== undefined) {
          delayMs = Math.max(delayMs, retryAfterSec * 1000);
        }

        delayMs = Math.min(delayMs, retryOpts.maxDelayMs ?? 30_000);
        await new Promise((r) => setTimeout(r, delayMs));
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
      return cached;
    }

    // Check for offline JWT lease verification
    if (this._config.daywalkerPublicKey && token.split(".").length === 3) {
      const jwtResult = await verifyJwtLease({
        token,
        publicKey: this._config.daywalkerPublicKey,
        expectedServiceSlug: serviceSlug || undefined,
        expectedIssuer: this._config.leaseIssuer ?? undefined,
      });

      if (jwtResult.valid && jwtResult.payload) {
        const payload = jwtResult.payload;
        const result: ValidateResult = {
          ok: true,
          data: {
            serviceSlug: serviceSlug || ((payload.serviceSlug || payload.aud || "") as string),
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
          },
        };

        if (this._config.cacheTtlMs > 0) {
          // Never cache a lease past its own expiry.
          this._cacheSet(cacheKey, result, this._config.cacheTtlMs, (payload.exp as number) * 1000);
        }
        return result;
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
    if (pending) return pending;
    const run = this._validateOnline(token, serviceSlug, cacheKey).finally(() => {
      this._inflight.delete(inflightKey);
    });
    this._inflight.set(inflightKey, run);
    return run;
  }

  private async _validateOnline(token: string, serviceSlug: string, cacheKey: string): Promise<ValidateResult> {
    const negTtl = this._config.negativeCacheTtlMs;
    const fail = (result: Extract<ValidateResult, { ok: false }>): ValidateResult => {
      if (negTtl > 0 && result.error !== "RATE_LIMITED" && result.error !== "NETWORK_ERROR") {
        this._cacheSet(cacheKey, result, negTtl);
      }
      return result;
    };
    try {
      const validateBody: Record<string, string> = { token };
      if (serviceSlug) {
        validateBody.serviceSlug = serviceSlug;
      }

      const res = await this.fetch("/api/v1/tokens/validate", {
        method: "POST",
        body: validateBody,
      });

      const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;

      if (res.status === 200 && json.valid !== false) {
        const payloadData = (typeof json.data === "object" && json.data ? json.data : json) as Record<string, unknown>;
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

      if (res.status === 429) {
        const retryAfter = parseRetryAfter(res.headers.get("retry-after")) ?? (json.retryAfter as number | undefined);
        return {
          ok: false,
          error: "RATE_LIMITED",
          status: 429,
          message: redactSecrets((json.message as string) || "Rate limit exceeded"),
          retryAfter,
        };
      }

      let error = "INVALID_TOKEN";
      const errMsg = (json.message || json.error || "") as string;
      if (json.error === "EXPIRED" || /expired/i.test(errMsg)) {
        error = "EXPIRED";
      } else if (json.error === "REVOKED" || /revoked/i.test(errMsg)) {
        error = "REVOKED";
      }

      return fail({
        ok: false,
        error,
        status: res.status,
        message: redactSecrets(errMsg || `Validation failed with HTTP ${res.status}`),
      });
    } catch (err) {
      return {
        ok: false,
        error: "NETWORK_ERROR",
        status: 503,
        message: redactSecrets(`Could not reach Daywalker Auth: ${(err as Error).message}`),
      };
    }
  }

  /**
   * Service health check: validates this service's own configured API key (DAYWALKER_API_KEY).
   * Never use this to authenticate an incoming request.
   */
  public async validateServiceKey(options?: { serviceSlug?: string; forceRefresh?: boolean }): Promise<ValidateResult> {
    if (!this._config.apiKey) {
      return {
        ok: false,
        error: "CONFIGURATION_ERROR",
        status: 500,
        message: "DAYWALKER_API_KEY is not set",
      };
    }
    return this.validateToken(this._config.apiKey, options);
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

  /**
   * Exchanges an RFC 9421 signed request for a short-lived EdDSA JWT lease (POST /api/v1/leases/issue).
   */
  public async issueLease(ttlSeconds?: number): Promise<{ lease: string; tokenType?: string; expiresAt?: string; jwksUri?: string }> {
    const res = await this.fetch("/api/v1/leases/issue", {
      method: "POST",
      body: ttlSeconds ? { ttlSeconds } : {},
    });
    const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
    if (res.status !== 201 && res.status !== 200) {
      throw new DaywalkerAuthError(redactSecrets(String(json.message || json.error || `Lease issue failed with HTTP ${res.status}`)), res.status, json.error as string | undefined);
    }
    return json as { lease: string; tokenType?: string; expiresAt?: string; jwksUri?: string };
  }

  /**
   * Fetches Daywalker's public JWKS (GET /.well-known/jwks.json) for offline lease verification.
   */
  public async fetchJwks(): Promise<{ keys: PublicJwk[] }> {
    const res = await globalThis.fetch(`${this._config.authUrl.replace(/\/+$/, "")}/.well-known/jwks.json`, { headers: { Accept: "application/json" } });
    if (!res.ok) throw new DaywalkerError(`Could not fetch JWKS (HTTP ${res.status})`, res.status);
    return (await res.json()) as { keys: PublicJwk[] };
  }

  /**
   * The public JWK(s) configured for this service.
   */
  public async keys(): Promise<{ keys: PublicJwk[] }> {
    const key = await this.getLoadedSigningKey();
    return { keys: key ? [key.publicJwk] : [] };
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

    const keyId = signingKey?.publicJwk.kid ?? null;
    const offlineVerificationReady = Boolean(this._config.daywalkerPublicKey);

    return {
      ok: problems.length === 0,
      serviceSlug: this._config.serviceSlug,
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
