import { DaywalkerError } from "./types.js";
import type { ConfigBundle, PublicJwk, PublicJwks } from "./types.js";
import { verifyJwtLease } from "./crypto/signatures.js";
import { webcrypto } from "./crypto/webcrypto.js";
import { base64ToBytes, hexToBytes, utf8ToString } from "./crypto/encoding.js";
import { assertSecureUrl } from "./secure-url.js";

/** A per-service rate limit as carried in the `service_limits` claim of an access token. */
export interface ServiceLimit {
  rateLimitPerMinute?: number | null;
  rateLimitPerHour?: number | null;
  [key: string]: unknown;
}

/** The claims of a Daywalker access token (`typ: at+jwt`) that the SDK knows about. */
export interface AccessTokenClaims {
  jti: string;
  exp: number;
  aud: string | string[];
  iss?: string;
  sub?: string;
  /** Every service the token covers. */
  services?: string[];
  /** Per-service limits, keyed by service slug. */
  service_limits?: Record<string, ServiceLimit>;
  cnf?: { jkt: string };
  user?: { id: string; name: string | null; email: string };
  [key: string]: unknown;
}

export interface VerifyAccessTokenOptions {
  token: string;
  /** Service the token must be issued for (`aud`). */
  serviceSlug: string;
  /** The JWKS from `${authUrl}/.well-known/jwks.json`, a single JWK, or a PEM/base64 key. */
  jwks: PublicJwks | PublicJwk | string | CryptoKey;
  issuer?: string;
  currentTime?: number;
}

export type VerifyAccessTokenResult =
  | { valid: true; claims: AccessTokenClaims; services: string[]; serviceLimits: Record<string, ServiceLimit> }
  | { valid: false; error: string };

/**
 * Verifies an access token locally against a JWKS: EdDSA only, `typ: at+jwt`, `aud` must contain `serviceSlug`,
 * `exp`/`nbf` are checked. DPoP-bound tokens (`cnf.jkt`) still need their proof checked (`verifyDpopProof`).
 */
export async function verifyAccessToken(options: VerifyAccessTokenOptions): Promise<VerifyAccessTokenResult> {
  const r = await verifyJwtLease({
    token: options.token,
    publicKey: options.jwks,
    expectedServiceSlug: options.serviceSlug,
    expectedIssuer: options.issuer,
    currentTime: options.currentTime,
  });
  if (!r.valid || !r.payload) return { valid: false, error: r.error ?? "invalid token" };
  const claims = r.payload as AccessTokenClaims;
  return { valid: true, claims, services: accessTokenServices(claims), serviceLimits: accessTokenServiceLimits(claims) };
}

/** The service slugs an access token covers (`services`, falling back to `aud`), lower-cased and de-duplicated. */
export function accessTokenServices(payload: Record<string, unknown>): string[] {
  const strings = (v: unknown) => (Array.isArray(v) ? v : typeof v === "string" ? [v] : []).filter((s): s is string => typeof s === "string");
  const listed = strings(payload.services);
  return Array.from(new Set((listed.length > 0 ? listed : strings(payload.aud)).map((s) => s.toLowerCase())));
}

/** The `service_limits` claim of an access token, keeping only well-formed entries. */
export function accessTokenServiceLimits(payload: Record<string, unknown>): Record<string, ServiceLimit> {
  const raw = payload.service_limits;
  const out: Record<string, ServiceLimit> = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) return out;
  for (const [slug, v] of Object.entries(raw as Record<string, unknown>)) {
    if (v && typeof v === "object" && !Array.isArray(v)) out[slug.toLowerCase()] = { ...(v as ServiceLimit) };
  }
  return out;
}

/** The `{ iv, tag, ciphertext }` (base64) body of `POST /api/v1/services/:slug/bundle`. */
export interface SealedBundle {
  iv: string;
  tag: string;
  ciphertext: string;
}

/** Opens a sealed config bundle (AES-256-GCM) with the hex `licenseKey`. Throws when the key or data is wrong. */
export async function unsealBundle(licenseKey: string, sealed: SealedBundle, serviceSlug?: string): Promise<ConfigBundle> {
  const key = await webcrypto.importKey("raw", hexToBytes(licenseKey) as BufferSource, { name: "AES-GCM" }, false, ["decrypt"]);
  const tag = base64ToBytes(sealed.tag);
  const data = base64ToBytes(sealed.ciphertext);
  const joined = new Uint8Array(data.length + tag.length);
  joined.set(data);
  joined.set(tag, data.length);
  const plain = await webcrypto.decrypt({ name: "AES-GCM", iv: base64ToBytes(sealed.iv) as BufferSource, tagLength: 128 }, key, joined as BufferSource);
  const parsed = JSON.parse(utf8ToString(new Uint8Array(plain))) as ConfigBundle;
  if (!parsed || typeof parsed !== "object" || typeof parsed.dataKeySalt !== "string" || (serviceSlug && parsed.serviceSlug !== serviceSlug.toLowerCase())) {
    throw new DaywalkerError("The bundle is malformed or belongs to another service");
  }
  return parsed;
}

export interface ManagementClientOptions {
  /** Daywalker base URL, e.g. `https://auth.daywalker.dev`. */
  authUrl: string;
  /** The user's session JWT (these endpoints don't accept API keys), or a function returning it per call. */
  sessionToken: string | (() => string | Promise<string>);
  fetch?: typeof fetch;
  timeoutMs?: number;
}

export interface ApiTokenRecord {
  id: string;
  name?: string;
  serviceId?: string;
  additionalServiceIds?: string[];
  allowedOrigins?: string[];
  expiresAt?: string | null;
  revokedAt?: string | null;
  createdAt?: string;
  [key: string]: unknown;
}

export interface CreateTokenInput {
  name: string;
  serviceId: string;
  /** More services this one token also covers. */
  additionalServiceIds?: string[];
  allowedOrigins?: string[];
  expiresAt?: Date | string | null;
}

export type UpdateTokenInput = Partial<Omit<CreateTokenInput, "serviceId">>;

export interface TokenLogQuery {
  limit?: number;
  cursor?: string;
  from?: Date | string;
  to?: Date | string;
  [key: string]: string | number | Date | undefined;
}

export interface TokenLogEntry {
  tokenId?: string;
  createdAt?: string;
  [key: string]: unknown;
}

export class DaywalkerManagementError extends DaywalkerError {
  constructor(message: string, status: number, public readonly code?: string) {
    super(message, status);
    this.name = "DaywalkerManagementError";
  }
}

const ID = /^[A-Za-z0-9_-]{1,128}$/;

/** Token management, usage logs and key management for the signed-in user (session JWT auth). */
export class DaywalkerManagementClient {
  readonly #base: string;
  readonly #auth: ManagementClientOptions["sessionToken"];
  readonly #fetch: typeof fetch;
  readonly #timeoutMs: number;

  constructor(options: ManagementClientOptions) {
    if (!options?.authUrl || !/^https?:\/\//i.test(options.authUrl)) throw new DaywalkerError("authUrl must be an http(s) URL");
    // The session JWT must never travel in cleartext: https only (http just for localhost), no credentials.
    try {
      assertSecureUrl("authUrl", options.authUrl);
    } catch (err) {
      throw new DaywalkerError((err as Error).message);
    }
    if (/[?#]/.test(options.authUrl)) throw new DaywalkerError("authUrl must not contain a query or fragment");
    if (!options.sessionToken) throw new DaywalkerError("sessionToken is required");
    this.#base = options.authUrl.replace(/\/+$/, "");
    this.#auth = options.sessionToken;
    this.#fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    this.#timeoutMs = options.timeoutMs ?? 10_000;
  }

  async #call<T>(method: string, path: string, body?: unknown, query?: Record<string, unknown>): Promise<T> {
    const url = new URL(`${this.#base}${path}`);
    for (const [k, v] of Object.entries(query ?? {})) {
      if (v !== undefined) url.searchParams.set(k, v instanceof Date ? v.toISOString() : String(v));
    }
    const jwt = typeof this.#auth === "function" ? await this.#auth() : this.#auth;
    const res = await this.#fetch(url, {
      method,
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(this.#timeoutMs),
      headers: { Accept: "application/json", Authorization: `Bearer ${jwt}`, ...(body !== undefined ? { "Content-Type": "application/json" } : {}) },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = res.status === 204 ? "" : await res.text();
    let json: any = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = null;
    }
    if (!res.ok) {
      const msg = typeof json?.message === "string" ? json.message : typeof json?.error === "string" ? json.error : "request failed";
      throw new DaywalkerManagementError(`${method} ${path} failed (HTTP ${res.status}): ${msg.slice(0, 300)}`, res.status, typeof json?.code === "string" ? json.code : undefined);
    }
    return json as T;
  }

  #id(id: string): string {
    if (!ID.test(id)) throw new DaywalkerError("invalid id");
    return encodeURIComponent(id);
  }

  #input(input: Record<string, unknown>): Record<string, unknown> {
    const out: Record<string, unknown> = { ...input };
    if (out.expiresAt instanceof Date) out.expiresAt = out.expiresAt.toISOString();
    return out;
  }

  /** `POST /api/v1/tokens`. The secret is only returned here, once. */
  createToken(input: CreateTokenInput): Promise<ApiTokenRecord & { token?: string }> {
    return this.#call("POST", "/api/v1/tokens", this.#input({ ...input }));
  }
  /** `GET /api/v1/tokens`. */
  listTokens(): Promise<ApiTokenRecord[] | { tokens: ApiTokenRecord[] }> {
    return this.#call("GET", "/api/v1/tokens");
  }
  /** `GET /api/v1/tokens/:id`. */
  getToken(id: string): Promise<ApiTokenRecord> {
    return this.#call("GET", `/api/v1/tokens/${this.#id(id)}`);
  }
  /** `PATCH /api/v1/tokens/:id`. */
  updateToken(id: string, input: UpdateTokenInput): Promise<ApiTokenRecord> {
    return this.#call("PATCH", `/api/v1/tokens/${this.#id(id)}`, this.#input({ ...input }));
  }
  /** Revokes a token (`DELETE /api/v1/tokens/:id`). */
  revokeToken(id: string): Promise<unknown> {
    return this.#call("DELETE", `/api/v1/tokens/${this.#id(id)}`);
  }
  /** `POST /api/v1/tokens/:id/connect`. */
  connectToken(id: string, body: Record<string, unknown> = {}): Promise<unknown> {
    return this.#call("POST", `/api/v1/tokens/${this.#id(id)}/connect`, body);
  }
  /** `GET /api/v1/tokens/logs`: usage logs across all tokens. */
  listTokenLogs(query: TokenLogQuery = {}): Promise<TokenLogEntry[] | { logs: TokenLogEntry[]; nextCursor?: string | null }> {
    return this.#call("GET", "/api/v1/tokens/logs", undefined, query);
  }
  /** `GET /api/v1/tokens/:id/logs`: usage logs of one token. */
  getTokenLogs(id: string, query: TokenLogQuery = {}): Promise<TokenLogEntry[] | { logs: TokenLogEntry[]; nextCursor?: string | null }> {
    return this.#call("GET", `/api/v1/tokens/${this.#id(id)}/logs`, undefined, query);
  }
  /** `POST /api/v1/keys/register` with the user's session. */
  registerKey(body: Record<string, unknown>): Promise<unknown> {
    return this.#call("POST", "/api/v1/keys/register", body);
  }
  /** `GET /api/v1/keys`. */
  listKeys(query: Record<string, string | undefined> = {}): Promise<unknown> {
    return this.#call("GET", "/api/v1/keys", undefined, query);
  }
  /** `DELETE /api/v1/keys/:keyId`. */
  revokeKey(keyId: string): Promise<unknown> {
    return this.#call("DELETE", `/api/v1/keys/${this.#id(keyId)}`);
  }
}

export function createManagementClient(options: ManagementClientOptions): DaywalkerManagementClient {
  return new DaywalkerManagementClient(options);
}
