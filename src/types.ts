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

/** The DPoP proof that came with an incoming `Authorization: DPoP <token>` request. */
export interface IncomingDpop {
  /** The `DPoP` header. */
  proof: string | null | undefined;
  method: string;
  /** The full request URL (its origin is replaced by `publicOrigin` when configured). */
  url: string;
}

export interface ValidateTokenOptions {
  serviceSlug?: string;
  forceRefresh?: boolean;
  offlineOnly?: boolean;
  /**
   * The request's DPoP proof. Required to accept a DPoP-bound (`cnf.jkt`) access token; the adapters pass
   * it for you. A bound token without a valid proof is refused with DPOP_REQUIRED / INVALID_DPOP_PROOF.
   */
  dpop?: IncomingDpop;
}

export type ValidateErrorCode =
  | "EXPIRED"
  | "REVOKED"
  | "INVALID_TOKEN"
  | "RATE_LIMITED"
  | "NETWORK_ERROR"
  | "SERVICE_UNAVAILABLE"
  | "CONFIGURATION_ERROR"
  | "SERVICE_NOT_GRANTED"
  | "DPOP_REQUIRED"
  | "INVALID_DPOP_PROOF"
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

/** A provisioned signing key as a `KeyStore` keeps it. Only keys already registered with Daywalker are stored. */
export interface StoredSigningKey {
  /** Record format version (1). */
  version: 1;
  /** RFC 7638 thumbprint of the public key; checked against the key on every load. */
  keyId: string;
  /** The domain the key is registered for. */
  domain: string;
  /** The Ed25519 private key, PKCS#8 DER in base64. */
  privateKeyPkcs8Base64: string;
  /** Unix seconds when it was registered. */
  createdAt: number;
}

/**
 * Where an auto-provisioned signing key lives between processes. On first use the client loads it; when
 * there is none it generates a key, registers it with Daywalker (`POST /api/v1/keys/register`) and saves it
 * with `saveIfAbsent`, which must be atomic (create-if-absent): when several instances start at once exactly
 * one save wins and the others load the winner's key. A store without `saveIfAbsent` is read-only.
 * Built in: `memoryKeyStore()` / `envKeyStore()` (`@shelbyb/daywalker-sdk/keystore`) and `fileKeyStore()`
 * (`@shelbyb/daywalker-sdk/keystore/file`); Redis (`SET key value NX`), KV or a secrets manager fit too.
 */
export interface KeyStore {
  load(): Promise<StoredSigningKey | null> | StoredSigningKey | null;
  /** Saves `key` unless one is already stored. True when this call saved it, false when another key was there. */
  saveIfAbsent?(key: StoredSigningKey): Promise<boolean> | boolean;
}

/**
 * Signs with a key held elsewhere, typically a KMS or HSM, so the private key never exists in this process,
 * its environment or its files. `sign` receives the RFC 9421 signature base and must return the raw 64-byte
 * Ed25519 signature. Register the public key once (`registerPublicKey`); pass `publicJwk` so the first
 * signature is checked against it before anything is sent.
 */
export interface MessageSigner {
  /** The registered key's id (its RFC 7638 thumbprint, or the id you registered it under). */
  keyId: string;
  sign(data: Uint8Array): Promise<Uint8Array>;
  publicJwk?: PublicJwk;
}

export interface DaywalkerConfig {
  /**
   * The OAuth client credential (env DAYWALKER_API_KEY). Sent only on the client credentials grant to
   * `POST /api/v1/oauth/token`; every other request carries a DPoP-bound access token.
   */
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
   * `"auto"` (env DAYWALKER_JWKS=auto) verifies access tokens offline against Daywalker's published key set,
   * fetched from `${authUrl}/.well-known/jwks.json` only and cached, so signing-key rotation needs no
   * redeploy. When no key set can be obtained, `daywalkerPublicKey` (if set) is used instead. Default off.
   */
  jwks?: "auto" | "off";
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
  /**
   * Origin clients use to reach this service (e.g. `https://api.example.com`), for checking the `htu` of
   * DPoP proofs that come with bound access tokens. Defaults to the request URL's origin; set it behind a
   * proxy or load balancer that rewrites the host.
   */
  publicOrigin?: string;
  /** Shared store for DPoP proof `jti`s (default: per-process memory). Needed with several instances. */
  dpopReplayStore?: ReplayStore;
  /**
   * Auto-provisioning: where the signing key is kept when `signingKey` / DAYWALKER_SIGNING_KEY isn't set.
   * On first use the client loads it from here, or generates one, registers it for `domain` with the API key
   * and saves it. Ignored when `signingKey` or `signer` is set.
   */
  keyStore?: KeyStore;
  /**
   * Ephemeral signing keys (env DAYWALKER_EPHEMERAL_KEY=true): the key is generated in memory, non-extractable,
   * registered for `domain` with a lifetime (`ttlSeconds`, default 6 hours; env DAYWALKER_KEY_TTL_SECONDS) in
   * this process's own slot (`instanceId`, default random; env DAYWALKER_INSTANCE_ID), and replaced in the
   * same slot before it expires. Nothing is stored anywhere. `close()` revokes it at shutdown. Daywalker allows
   * 20 live keys per domain, so give long-lived instances a stable `instanceId` (a restart then replaces its
   * previous key) and prefer a shared `keyStore` for serverless. Can't be combined with `keyStore`.
   */
  ephemeralKey?: boolean | { ttlSeconds?: number; instanceId?: string };
  /** Signs requests with an external key (KMS / HSM) instead of a local one. Takes precedence over everything. */
  signer?: MessageSigner;
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

/** A service's license key from Daywalker: derived per service, signing key and one-hour window. */
export interface License {
  serviceSlug: string;
  /** 64 hex characters (32 bytes). A secret: never log it or send it anywhere. */
  licenseKey: string;
  /** ISO 8601: the end of the window the key is valid for. */
  expiresAt: string;
}

/** The config bundle Daywalker seals under the license key. Fields beyond these are passed through. */
export interface ConfigBundle {
  serviceSlug: string;
  /** Random per issue; derive per-process secrets from it (and the license key), never store it. */
  dataKeySalt: string;
  features: { exclusiveTier?: boolean; stage?: string; rateLimitPerMinute?: number | null; rateLimitPerHour?: number | null; [key: string]: unknown };
  issuedAt: string;
  expiresAt: string;
  [key: string]: unknown;
}

export interface LicenseOptions {
  /** Default: the configured service slug. */
  serviceSlug?: string;
  /** Ignore the cached license and start a new client credentials grant. */
  forceRefresh?: boolean;
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
  /** The local key to sign with. Not needed (and ignored) when `signer` is given. */
  key?: SigningKey | string;
  /** Signs with an external key instead (KMS / HSM); `keyid` defaults to `signer.keyId`. */
  signer?: MessageSigner;
  created?: number;
  keyid?: string;
  alg?: string;
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
