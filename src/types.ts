import { redactSecrets } from "./crypto/encoding.js";

export interface RateLimitWindow {
  limit: number;
  remaining: number;
  reset: number;
}

export interface TokenPayload {
  serviceSlug: string;
  tenantId: string;
  rateLimit: RateLimitWindow;
  rateLimitHourly?: RateLimitWindow;
  tokenId?: string;
  tokenName?: string;
  userId?: string;
  stage?: string;
  /**
   * Every service slug the token (or JWT lease) covers. One API key can cover several services, so this
   * can hold more than `serviceSlug`, which is the service this call validated for.
   */
  services?: string[];
  offlineVerified?: boolean;
  [key: string]: unknown;
}

export type ValidateErrorCode =
  | "EXPIRED"
  | "REVOKED"
  | "INVALID_TOKEN"
  | "RATE_LIMITED"
  | "NETWORK_ERROR"
  | "SERVICE_UNAVAILABLE"
  | "CONFIGURATION_ERROR"
  | string;

/**
 * Failures that say nothing about the token: Daywalker Auth was unreachable, timed out, answered 5xx
 * or answered with something that isn't a validation result. Both carry status 503 and are never cached;
 * adapters should answer 503 rather than 401 for them.
 */
export const UNAVAILABLE_ERROR_CODES: readonly ValidateErrorCode[] = Object.freeze(["SERVICE_UNAVAILABLE", "NETWORK_ERROR"]);

export type ValidateResult =
  | {
      ok: true;
      data: TokenPayload;
    }
  | {
      ok: false;
      error: ValidateErrorCode;
      status: number;
      message: string;
      retryAfter?: number;
    };

export interface PublicJwks {
  keys: PublicJwk[];
}

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  use?: "sig";
  alg?: "EdDSA" | "ed25519";
}

export interface SigningKey {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: PublicJwk;
  privateKeyPkcs8Base64?: string;
}

export interface RetryOptions {
  maxRetries?: number;
  initialDelayMs?: number;
  /** Cap on the exponential backoff delay. Default 30000ms. */
  maxDelayMs?: number;
  backoffFactor?: number;
  jitter?: boolean;
  /**
   * Longest `Retry-After` honored on a 429 (default 60000ms). A longer one is not waited out:
   * the 429 response is returned to the caller.
   */
  maxRetryAfterMs?: number;
  /**
   * Retry after network errors / timeouts. Defaults to true only for GET, HEAD and OPTIONS (or when an
   * `idempotencyKey` is given), since the server may already have processed a request whose response was lost.
   */
  retryNetworkErrors?: boolean;
}

export interface DaywalkerConfig {
  apiKey?: string;
  signingKey?: string | SigningKey;
  /**
   * Previous private key during rotation (env DAYWALKER_SIGNING_KEY_PREVIOUS). Never used to sign; its public
   * JWK is published by `keys()` next to the current one so requests from instances still on the old key verify.
   */
  previousSigningKey?: string | SigningKey;
  keyId?: string;
  /**
   * The service this deployment validates tokens for (env DAYWALKER_SERVICE_SLUG). One API key can cover
   * several services: a comma-separated list ("gigpulse,devpulse") is accepted, and the first is the default.
   */
  serviceSlug?: string;
  /** Same as a comma-separated `serviceSlug`, as an array. Takes precedence over `serviceSlug`. */
  serviceSlugs?: string[];
  domain?: string;
  /** A JWK, a JWKS (`{ keys: [...] }`, selected by the lease's `kid`), PEM, or Base64 SPKI / raw key. */
  daywalkerPublicKey?: string | PublicJwk | PublicJwks;
  /**
   * Expected `iss` of offline-verified JWT leases (env DAYWALKER_LEASE_ISSUER). Daywalker documents no fixed
   * issuer, so `iss` is unchecked when unset; set it whenever leases from other issuers could share your key.
   */
  leaseIssuer?: string;
  /** Must be https:// (http:// only for localhost). */
  authUrl?: string;
  cacheTtlMs?: number;
  /** Short cache for failed validations (not 429/network errors). Default 3000ms; 0 disables. */
  negativeCacheTtlMs?: number;
  maxRetries?: number;
  /** Defaults for `fetch()` retries; per-request `init.retry` overrides individual fields. */
  retry?: RetryOptions;
  /** Per-attempt timeout for requests to Daywalker Auth. Default 5000ms; 0 disables. */
  timeoutMs?: number;
  fetch?: typeof fetch;
  env?: Record<string, string | undefined>;
}

/** Tokens from the client credentials flow (POST /api/v1/oauth/token). */
export interface TokenSet {
  /** Short-lived (5-15 min) EdDSA JWT. Verify it with Daywalker's public JWKS. */
  accessToken: string;
  /** Single use: every refresh returns a new one. Keep it server-side. */
  refreshToken: string;
  tokenType: string;
  /** Unix seconds. */
  expiresAt: number;
  expiresIn: number;
  /** Seconds until the session ends and the client credentials must be used again. */
  refreshExpiresIn: number;
  scope: string;
  /** Every service slug the access token covers (also its `services` and `aud` claims). */
  services: string[];
  jwksUri?: string;
}

export interface GetTokensOptions {
  /** Narrow the grant to these service slugs (least privilege); default: every service the credentials cover. */
  scope?: string[];
  /** Access token lifetime in seconds (Daywalker clamps it to 300-900). */
  expiresIn?: number;
}

/** The `user` claim of an access token. */
export interface AccessTokenUser {
  /** The user's public UUID v7. */
  id: string;
  name: string | null;
  email: string;
}

export interface SelfCheckResult {
  ok: boolean;
  serviceSlug: string | null;
  serviceSlugs: string[];
  domain: string | null;
  signing: boolean;
  keyId: string | null;
  offlineVerificationReady: boolean;
  problems: string[];
}

export interface SignedHeaders {
  "Content-Digest"?: string;
  "Signature-Input": string;
  Signature: string;
  Authorization?: string;
  [key: string]: string | undefined;
}

export interface SignRequestParams {
  method: string;
  /** Request target path; a query string (`/a?b=1`) is split off and covered as "@query". */
  path: string;
  authority: string;
  body?: string | Uint8Array | null;
  key: SigningKey | string;
  created?: number;
  keyid?: string;
  alg?: string;
  /** Sets `Authorization: Bearer <apiKey>` on the returned headers (not covered by the signature). */
  apiKey?: string;
  /** Must be 1-128 of `[A-Za-z0-9_.-]` so it can't inject Signature-Input parameters. */
  nonce?: string;
}

/**
 * Remembers verified request signatures until they expire. The default in-memory store is per process:
 * deployments with several instances must pass a shared store (e.g. Redis `SET key 1 NX PX ttl`), or a
 * signature replayed against another instance is accepted there.
 */
export interface ReplayStore {
  /** True when `key` was recorded and has not expired yet. */
  has(key: string): boolean | Promise<boolean>;
  /**
   * Atomically records `key` for `ttlMs` if it is absent. Returns false when the key is already present or
   * the store can't take it (e.g. full); the signature is then rejected.
   */
  record(key: string, ttlMs: number): boolean | Promise<boolean>;
}

export interface VerifySignatureParams {
  method: string;
  /** Request target path, including any query string (covered as "@query"). */
  path: string;
  authority: string;
  headers: Record<string, string | undefined> | Headers;
  body?: string | Uint8Array | null;
  /** A JWK, a JWKS (selected by the signature's `keyid`), a CryptoKey, PEM or Base64 key. */
  publicKey: PublicJwk | PublicJwks | CryptoKey | string;
  currentTime?: number;
  maxClockSkewSeconds?: number;
  replayCheck?: boolean;
  /** Where verified signatures are remembered; defaults to a per-process in-memory cache. */
  replayStore?: ReplayStore;
}

export interface VerifySignatureResult {
  valid: boolean;
  keyid?: string;
  error?: string;
}

export class DaywalkerError extends Error {
  public readonly status?: number;
  public readonly code?: string;

  constructor(message: string, status?: number, code?: string) {
    const cleanMessage = redactSecrets(message);
    super(cleanMessage);
    this.name = "DaywalkerError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: redactSecrets(this.message),
      status: this.status,
      code: this.code,
    };
  }

  public [Symbol.for("nodejs.util.inspect.custom")](): Record<string, unknown> {
    return this.toJSON();
  }
}

export class DaywalkerAuthError extends DaywalkerError {
  constructor(message: string, status = 401, code: ValidateErrorCode = "INVALID_TOKEN") {
    super(message, status, code);
    this.name = "DaywalkerAuthError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class DaywalkerRateLimitError extends DaywalkerError {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number) {
    super(message, 429, "RATE_LIMITED");
    this.name = "DaywalkerRateLimitError";
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  public override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      retryAfter: this.retryAfter,
    };
  }
}
