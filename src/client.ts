import { parseServiceSlugs, resolveConfig, type ResolvedConfig } from "./config.js";
import { API_KEY_PATTERN, SAFE_IDENTIFIER_PATTERN, SERVICE_SLUG_PATTERN } from "./crypto/signatures.js";
import { parseStoredSigningKey } from "./keystore/index.js";
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
  verifyDpopProof,
  importSigningKey,
  generateSigningKey,
  registerPublicKey,
  revokeSigningKey,
  keySlotFor,
  randomInstanceId,
  calculateJwkThumbprint,
  base64UrlToBytes,
  base64ToBytes,
  hexToBytes,
  utf8ToString,
  type DpopKey,
} from "./crypto/index.js";
import { webcrypto } from "./crypto/webcrypto.js";
import {
  DaywalkerAuthError,
  DaywalkerError,
  DaywalkerRateLimitError,
  type DaywalkerConfig,
  type IncomingDpop,
  type ReplayStore,
  type ValidateTokenOptions,
  type KeyStore,
  type MessageSigner,
  type StoredSigningKey,
  type TokenSet,
  type GetTokensOptions,
  type License,
  type LicenseOptions,
  type ConfigBundle,
  type PublicJwk,
  type PublicJwks,
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
  webcrypto.getRandomValues(bytes);
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

/**
 * Reads a response body as text, giving up (and cancelling it) after `timeoutMs` so a trickling body can't
 * hang us, and refusing bodies over `MAX_RESPONSE_BYTES` so a huge one can't exhaust memory.
 */
async function readText(res: Response, timeoutMs: number): Promise<string> {
  const declared = Number(res.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    res.body?.cancel().catch(() => {});
    throw new DaywalkerError(`Daywalker Auth response is too large (${declared} bytes)`);
  }
  const read = async (): Promise<string> => {
    if (!res.body) return res.text();
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_RESPONSE_BYTES) {
        reader.cancel().catch(() => {});
        throw new DaywalkerError(`Daywalker Auth response is larger than ${MAX_RESPONSE_BYTES} bytes`);
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(total);
    let offset = 0;
    for (const c of chunks) {
      bytes.set(c, offset);
      offset += c.byteLength;
    }
    return utf8ToString(bytes);
  };
  if (!(timeoutMs > 0)) return read();
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => {
      res.body?.cancel().catch(() => {});
      reject(new DOMException(`Reading the Daywalker Auth response timed out after ${timeoutMs}ms`, "TimeoutError"));
    }, timeoutMs);
  });
  try {
    return await Promise.race([read(), timeout]);
  } finally {
    clearTimeout(timer);
  }
}

/** A JSON object from a response body (bounded, with a timeout), or `{}` when it isn't one. */
async function readJsonObject(res: Response, timeoutMs: number): Promise<Record<string, unknown>> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(await readText(res, timeoutMs));
  } catch (err) {
    if ((err as Error).name === "TimeoutError" || err instanceof DaywalkerError) throw err;
    return {};
  }
  return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
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
function credentialFailure(err: DaywalkerAuthError | DaywalkerError): ValidateResult {
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

/**
 * Longest a successful validation is cached (5 minutes), whatever `cacheTtlMs` says, so a revoked token
 * can't stay accepted for long.
 */
export const MAX_CACHE_TTL_MS = 300_000;
/** Longest incoming token accepted (characters); longer input is refused without calling Daywalker. */
export const MAX_TOKEN_LENGTH = 8_192;
/** Printable ASCII with no whitespace, quotes, commas or separators: anything else is not a token. */
const TOKEN_PATTERN = /^[A-Za-z0-9._~+/=-]+$/;
/** Access tokens are used for at most this long (seconds), whatever the token endpoint says. */
const MAX_ACCESS_TOKEN_LIFETIME_SECONDS = 3_600;
/** Largest response body read from Daywalker Auth. */
const MAX_RESPONSE_BYTES = 1_048_576;

/** How long a fetched JWKS (`jwks: "auto"`) is used before it is refetched. */
export const JWKS_CACHE_TTL_MS = 600_000;
/**
 * Least time between two JWKS fetches, whatever triggers them (an unknown `kid`, an expired set, a failed
 * fetch), so a flood of tokens naming made-up `kid`s costs at most one request to Daywalker per interval.
 */
export const JWKS_REFETCH_COOLDOWN_MS = 30_000;
/** Keys looked at in a fetched JWKS; the rest are ignored. */
const MAX_JWKS_KEYS = 16;
/** An Ed25519 public key: 32 bytes, unpadded base64url. */
const ED25519_X_PATTERN = /^[A-Za-z0-9_-]{43}$/;

/**
 * The keys of a fetched JWKS that can verify Daywalker access tokens: Ed25519 signing keys for EdDSA with a
 * `kid`, copied to fresh objects with nothing else on them. Anything else (RSA, EC, `alg: "none"`, private
 * key material, encryption keys) is dropped.
 */
function usableJwks(keys: unknown): PublicJwk[] {
  if (!Array.isArray(keys)) return [];
  const out: PublicJwk[] = [];
  for (const k of keys.slice(0, MAX_JWKS_KEYS)) {
    if (!k || typeof k !== "object") continue;
    const j = k as Record<string, unknown>;
    if (j.kty !== "OKP" || j.crv !== "Ed25519" || typeof j.x !== "string" || !ED25519_X_PATTERN.test(j.x)) continue;
    if ((j.alg !== undefined && j.alg !== "EdDSA") || (j.use !== undefined && j.use !== "sig") || j.d !== undefined) continue;
    if (typeof j.kid !== "string" || j.kid === "" || j.kid.length > 256) continue;
    out.push({ kty: "OKP", crv: "Ed25519", x: j.x, kid: j.kid, use: "sig", alg: "EdDSA" });
  }
  return out;
}

/** The `kid` a JWT's (unverified) header names, used only to pick a key; undefined when there is none. */
function jwtKid(token: string): string | undefined {
  try {
    const header = JSON.parse(utf8ToString(base64UrlToBytes(token.split(".")[0] ?? "")));
    return header && typeof header === "object" && typeof header.kid === "string" ? header.kid : undefined;
  } catch {
    return undefined;
  }
}

/** A copy of `value` that can't be changed: nested objects and arrays are frozen too. */
function deepFreeze<T>(value: T): T {
  if (value && typeof value === "object" && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const v of Object.values(value)) deepFreeze(v);
  }
  return value;
}

/** A `KeyStore` with its methods bound at construction. */
type CapturedKeyStore = Readonly<{ load: KeyStore["load"]; saveIfAbsent?: NonNullable<KeyStore["saveIfAbsent"]> }>;

/** What signs this client's requests, and where it came from. */
type SignerSource = "signer" | "signingKey" | "ephemeral" | "keyStore";
type ActiveSigner = Readonly<{ signer: MessageSigner; publicJwk?: PublicJwk; source: SignerSource }>;

/** A local key as a signer; its private key never leaves the closure. */
function localSigner(key: Pick<SigningKey, "privateKey" | "publicJwk">, keyId: string, source: Exclude<SignerSource, "signer">): ActiveSigner {
  const privateKey = key.privateKey;
  return Object.freeze({
    signer: Object.freeze({
      keyId,
      sign: async (data: Uint8Array) => new Uint8Array(await webcrypto.sign("Ed25519", privateKey, data as BufferSource)),
      publicJwk: key.publicJwk,
    }),
    publicJwk: key.publicJwk,
    source,
  });
}

export class Daywalker {
  readonly #config: ResolvedConfig;
  /** The secret-free, frozen view handed out by `config`. */
  readonly #publicConfig: Readonly<ResolvedConfig>;
  readonly #fetch: typeof fetch;
  readonly #publicOrigin: string | null;
  readonly #dpopReplayStore: ReplayStore | undefined;
  /** `config.signer` and `config.keyStore`, captured (methods bound) at construction so later edits can't swap them. */
  readonly #externalSigner: MessageSigner | null;
  readonly #keyStore: CapturedKeyStore | null;
  #signerPromise: Promise<ActiveSigner | null> | null = null;
  /** Ephemeral mode: this process's key slot, its current key, the rotation in flight, and when to retry one. */
  readonly #ephemeralSlot: string | null;
  #ephemeral: { signer: ActiveSigner; keyId: string; expiresAt: number } | null = null;
  #ephemeralRotation: Promise<ActiveSigner> | null = null;
  #ephemeralRetryAt = 0;
  /** Bumped whenever the ephemeral key is replaced; tokens requested under an older generation are stale. */
  #keyGeneration = 0;
  #closed = false;
  #signingKeyPromise?: Promise<SigningKey>;
  #previousSigningKeyPromise?: Promise<SigningKey>;
  readonly #cache = new Map<string, { result: ValidateResult; expiresAt: number; jkt?: string }>();
  readonly #inflight = new Map<string, Promise<ValidateResult>>();
  /** The last JWKS fetched with usable keys (`jwks: "auto"`), kept when a later fetch fails. */
  #jwks: { set: PublicJwks; fetchedAt: number } | null = null;
  #jwksFlight: Promise<void> | null = null;
  #jwksAttemptAt = -Infinity;

  constructor(config: DaywalkerConfig = {}) {
    // Everything is read once: changing the caller's config object later has no effect.
    const resolved = resolveConfig(config);
    resolved.cacheTtlMs = Math.max(0, Math.min(Number.isFinite(resolved.cacheTtlMs) ? resolved.cacheTtlMs : 0, MAX_CACHE_TTL_MS));
    resolved.negativeCacheTtlMs = Math.max(0, Math.min(Number.isFinite(resolved.negativeCacheTtlMs) ? resolved.negativeCacheTtlMs : 0, MAX_CACHE_TTL_MS));
    // Copies, so freezing never touches objects the caller still owns.
    const copyKey = (k: string | SigningKey | null) => (k && typeof k === "object" ? { ...k, publicJwk: { ...k.publicJwk } } : k);
    resolved.signingKey = copyKey(resolved.signingKey);
    resolved.previousSigningKey = copyKey(resolved.previousSigningKey);
    if (resolved.daywalkerPublicKey && typeof resolved.daywalkerPublicKey === "object") {
      resolved.daywalkerPublicKey = JSON.parse(JSON.stringify(resolved.daywalkerPublicKey));
    }
    this.#config = deepFreeze(resolved);
    this.#publicConfig = deepFreeze({
      ...resolved,
      serviceSlugs: [...resolved.serviceSlugs],
      retry: { ...resolved.retry },
      problems: [...resolved.problems],
      apiKey: resolved.apiKey ? "[configured]" : null,
      signingKey: resolved.signingKey ? "[configured]" : null,
      previousSigningKey: resolved.previousSigningKey ? "[configured]" : null,
    });
    const doFetch = config.fetch ?? globalThis.fetch;
    if (typeof doFetch !== "function") throw new DaywalkerError("No fetch implementation available: pass config.fetch");
    this.#fetch = doFetch;
    this.#publicOrigin = resolved.publicOrigin;
    this.#dpopReplayStore = config.dpopReplayStore;
    const signer = config.signer;
    if (signer) {
      if (typeof signer.sign !== "function" || typeof signer.keyId !== "string" || !SAFE_IDENTIFIER_PATTERN.test(signer.keyId)) {
        throw new DaywalkerError("config.signer needs a sign() function and a keyId of 1-128 safe characters");
      }
      this.#externalSigner = Object.freeze({
        keyId: signer.keyId,
        sign: signer.sign.bind(signer),
        publicJwk: signer.publicJwk ? Object.freeze({ ...signer.publicJwk }) : undefined,
      });
    } else {
      this.#externalSigner = null;
    }
    const store = config.keyStore;
    if (store && typeof store.load !== "function") throw new DaywalkerError("config.keyStore needs a load() function");
    if (store && resolved.ephemeralKey) throw new DaywalkerError("Use either keyStore or ephemeralKey, not both");
    this.#ephemeralSlot = resolved.ephemeralKey ? (resolved.ephemeralKey.instanceId ?? randomInstanceId()) : null;
    this.#keyStore = store
      ? Object.freeze({
          load: store.load.bind(store),
          saveIfAbsent: typeof store.saveIfAbsent === "function" ? store.saveIfAbsent.bind(store) : undefined,
        })
      : null;
    // Instances of this class (not subclasses, which may still add fields) can't gain or change properties.
    if (new.target === Daywalker) Object.freeze(this);
  }

  /** The resolved configuration, frozen, with the API key and private keys shown as "[configured]". */
  public get config(): Readonly<ResolvedConfig> {
    return this.#publicConfig;
  }

  public toJSON(): Record<string, unknown> {
    return {
      serviceSlug: this.#config.serviceSlug,
      domain: this.#config.domain,
      authUrl: this.#config.authUrl,
      keyId: this.#config.keyId,
      apiKey: maskSecret(this.#config.apiKey),
      signingKey: this.#config.signingKey ? "[configured]" : null,
      daywalkerPublicKey: this.#config.daywalkerPublicKey ? "[configured]" : null,
      jwks: this.#config.jwks,
    };
  }

  // Node.js custom inspect masking
  public [Symbol.for("nodejs.util.inspect.custom")](): Record<string, unknown> {
    return this.toJSON();
  }

  async #getLoadedSigningKey(): Promise<SigningKey | null> {
    if (!this.#config.signingKey) return null;
    if (typeof this.#config.signingKey !== "string" && "privateKey" in this.#config.signingKey) {
      return this.#config.signingKey;
    }
    if (!this.#signingKeyPromise) {
      this.#signingKeyPromise = loadSigningKey(this.#config.signingKey as string);
    }
    return this.#signingKeyPromise;
  }

  /**
   * What signs this client's requests, resolved once: `config.signer` (KMS / HSM), else `signingKey`
   * (DAYWALKER_SIGNING_KEY), else the key in `keyStore`, provisioned on first use. Null when none is set up.
   * A failure isn't remembered, so the next request tries again.
   */
  #getSigner(): Promise<ActiveSigner | null> {
    if (this.#closed) return Promise.reject(new DaywalkerError("This Daywalker client was closed", undefined, "CLIENT_CLOSED"));
    if (this.#config.ephemeralKey && !this.#externalSigner && !this.#config.signingKey) return this.#ephemeralSigner();
    if (!this.#signerPromise) {
      this.#signerPromise = this.#resolveSigner().catch((err) => {
        this.#signerPromise = null;
        throw err;
      });
    }
    return this.#signerPromise;
  }

  async #resolveSigner(): Promise<ActiveSigner | null> {
    const external = this.#externalSigner;
    if (external) {
      if (external.publicJwk) {
        // Prove once that the signer's key is the one claimed, before any request depends on it.
        const { publicKey } = await loadPublicKey(external.publicJwk);
        const challenge = webcrypto.getRandomValues(new Uint8Array(32));
        const signature = await external.sign(challenge);
        if (!(signature instanceof Uint8Array) || !(await webcrypto.verify("Ed25519", publicKey, signature as BufferSource, challenge as BufferSource))) {
          throw new DaywalkerAuthError("config.signer does not sign with the key in its publicJwk", 500, "CONFIGURATION_ERROR");
        }
      }
      return Object.freeze({ signer: external, publicJwk: external.publicJwk, source: "signer" as const });
    }
    const local = await this.#getLoadedSigningKey();
    if (local) return localSigner(local, this.#config.keyId ?? local.publicJwk.kid, "signingKey");
    if (this.#keyStore) {
      const key = await this.#provisionFromStore(this.#keyStore);
      return localSigner(key, key.publicJwk.kid, "keyStore");
    }
    return null;
  }

  async #loadStored(store: CapturedKeyStore): Promise<StoredSigningKey | null> {
    const raw = await store.load();
    return raw === null || raw === undefined ? null : parseStoredSigningKey(raw);
  }

  /** Imports a stored key (non-extractable) after checking it belongs to this service and matches its keyId. */
  async #useStored(stored: StoredSigningKey): Promise<SigningKey> {
    if (this.#config.domain && stored.domain !== this.#config.domain) {
      throw new DaywalkerAuthError(
        `The stored signing key is registered for ${stored.domain}, but this service is ${this.#config.domain}. Remove it from the key store to provision one for ${this.#config.domain}.`,
        500,
        "CONFIGURATION_ERROR"
      );
    }
    const key = await importSigningKey(stored.privateKeyPkcs8Base64);
    if (key.publicJwk.kid !== stored.keyId) {
      throw new DaywalkerAuthError("The stored signing key does not match its keyId (corrupted or tampered with)", 500, "CONFIGURATION_ERROR");
    }
    return key;
  }

  /**
   * Auto-provisioning. Loads the key from the store; when there is none, generates one, registers it for this
   * service's domain (`POST /api/v1/keys/register`, with the API key) and saves it with `saveIfAbsent`. Only
   * registered keys are ever stored, so a key planted in the store is never registered by this process. If
   * another instance saved first, its key is used and the one registered here is reported for revocation.
   */
  async #provisionFromStore(store: CapturedKeyStore): Promise<SigningKey> {
    const existing = await this.#loadStored(store);
    if (existing) return this.#useStored(existing);
    if (!store.saveIfAbsent) {
      throw new DaywalkerAuthError("The key store is read-only and holds no signing key: provision one with `npx daywalker init`", 500, "CONFIGURATION_ERROR");
    }
    if (!this.#config.apiKey) {
      throw new DaywalkerAuthError("DAYWALKER_API_KEY is needed to register a signing key on first use", 500, "CONFIGURATION_ERROR");
    }
    const domain = this.#config.domain;
    if (!domain) {
      throw new DaywalkerAuthError("No public domain detected to register a signing key for: set DAYWALKER_DOMAIN", 500, "CONFIGURATION_ERROR");
    }

    const generated = await generateSigningKey();
    // Another instance may have finished while we generated: prefer its key over registering a second one.
    const raced = await this.#loadStored(store);
    if (raced) return this.#useStored(raced);

    // Its own slot, so registering it never demotes a key another instance is already using.
    await this.#register(generated.publicJwk, { instanceId: keySlotFor(generated.publicJwk.kid) });

    const record: StoredSigningKey = {
      version: 1,
      keyId: generated.publicJwk.kid,
      domain,
      privateKeyPkcs8Base64: generated.privateKeyPkcs8Base64!,
      createdAt: Math.floor(Date.now() / 1000),
    };
    if (await store.saveIfAbsent(record)) return this.#useStored(record);

    const winner = await this.#loadStored(store);
    if (!winner) throw new DaywalkerAuthError("The key store refused the signing key but holds none", 500, "CONFIGURATION_ERROR");
    // Another instance stored its key first: ours was registered but will never be used, so revoke it.
    const revoked = await revokeSigningKey({ authUrl: this.#config.authUrl, apiKey: this.#config.apiKey, keyId: record.keyId, fetchFn: this.#fetch });
    if (!revoked.ok) {
      console.warn(`[daywalker] Unused signing key ${record.keyId} (${domain}) could not be revoked (${revoked.status} ${revoked.error}); revoke it with \`npx daywalker revoke ${record.keyId}\`.`);
    }
    return this.#useStored(winner);
  }

  /**
   * Ephemeral mode: the current in-memory key, replaced in the same slot once a quarter of its lifetime is left.
   * While the old key is still good for more than a minute, requests keep using it and the replacement registers
   * in the background (Daywalker keeps the old one valid for 10 more minutes). A failed replacement is retried
   * at most every 30 seconds.
   */
  async #ephemeralSigner(): Promise<ActiveSigner> {
    const now = Math.floor(Date.now() / 1000);
    const ttl = this.#config.ephemeralKey!.ttlSeconds;
    const current = this.#ephemeral;
    if (current && current.expiresAt - now > ttl / 4) return current.signer;
    const usable = current && current.expiresAt - now > 60;
    if (usable && Date.now() < this.#ephemeralRetryAt) return current.signer;
    if (!this.#ephemeralRotation) {
      this.#ephemeralRotation = this.#rotateEphemeral()
        .catch((err) => {
          this.#ephemeralRetryAt = Date.now() + 30_000;
          throw err;
        })
        .finally(() => {
          this.#ephemeralRotation = null;
        });
    }
    if (usable) {
      this.#ephemeralRotation.catch(() => {});
      return current.signer;
    }
    return this.#ephemeralRotation;
  }

  /** Generates a non-extractable key in memory and registers it in this process's slot with a lifetime. */
  async #rotateEphemeral(): Promise<ActiveSigner> {
    if (!this.#config.apiKey) {
      throw new DaywalkerAuthError("DAYWALKER_API_KEY is needed to register an ephemeral signing key", 500, "CONFIGURATION_ERROR");
    }
    if (!this.#config.domain) {
      throw new DaywalkerAuthError("No public domain detected to register a signing key for: set DAYWALKER_DOMAIN", 500, "CONFIGURATION_ERROR");
    }
    const ttl = this.#config.ephemeralKey!.ttlSeconds;
    const pair = (await webcrypto.generateKey({ name: "Ed25519" } as any, false, ["sign", "verify"])) as CryptoKeyPair;
    const { x } = (await webcrypto.exportKey("jwk", pair.publicKey)) as { x: string };
    const kid = await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x });
    const publicJwk: PublicJwk = { kty: "OKP", crv: "Ed25519", x, kid, use: "sig", alg: "EdDSA" };
    const registration = await this.#register(publicJwk, { instanceId: this.#ephemeralSlot!, ttlSeconds: ttl });
    if (this.#closed) {
      // close() ran while this registered: don't leave the key behind.
      await revokeSigningKey({ authUrl: this.#config.authUrl, apiKey: this.#config.apiKey, keyId: kid, fetchFn: this.#fetch });
      throw new DaywalkerError("This Daywalker client was closed", undefined, "CLIENT_CLOSED");
    }
    const now = Math.floor(Date.now() / 1000);
    const expiresAt = Math.min(registration.key?.expiresAt ?? Infinity, now + ttl);
    const signer = localSigner({ privateKey: pair.privateKey, publicJwk }, kid, "ephemeral");
    const replaced = this.#ephemeral !== null;
    this.#ephemeral = { signer, keyId: kid, expiresAt };
    // OAuth sessions are tied to the key that started them: tokens from before this point are now stale, even a
    // grant still in flight, so the next accessToken() starts a session with the new key.
    if (replaced) this.#keyGeneration++;
    return signer;
  }

  /**
   * Shuts the client down: revokes its ephemeral signing key (which also ends the OAuth sessions it started)
   * and forgets its tokens. Afterwards every call that needs Daywalker fails with CLIENT_CLOSED. Safe to call
   * twice. Keys from `signingKey`, `keyStore` or `signer` are long-lived and are left alone.
   */
  public async close(): Promise<{ revoked: string[]; failed: string[] }> {
    if (this.#closed) return { revoked: [], failed: [] };
    this.#closed = true;
    await this.#ephemeralRotation?.catch(() => {});
    const current = this.#ephemeral;
    this.#ephemeral = null;
    this.#tokens = null;
    if (!current || !this.#config.apiKey) return { revoked: [], failed: [] };
    const result = await revokeSigningKey({ authUrl: this.#config.authUrl, apiKey: this.#config.apiKey, keyId: current.keyId, fetchFn: this.#fetch });
    return result.ok ? { revoked: [current.keyId], failed: [] } : { revoked: [], failed: [current.keyId] };
  }

  /**
   * Registers a public key with Daywalker for this service's domain. Failures become errors the validation
   * paths map to 503 (an outage, or credentials Daywalker refuses), with Daywalker's code in the message and
   * what to do about a full domain.
   */
  async #register(publicJwk: PublicJwk, options: { instanceId: string; ttlSeconds?: number }) {
    const registration = await registerPublicKey({
      authUrl: this.#config.authUrl,
      apiKey: this.#config.apiKey!,
      domain: this.#config.domain,
      serviceSlug: this.#config.serviceSlugs.length > 0 ? this.#config.serviceSlugs.join(",") : undefined,
      publicJwk,
      instanceId: options.instanceId,
      ttlSeconds: options.ttlSeconds,
      fetchFn: this.#fetch,
    });
    if (registration.ok) return registration;
    const hint =
      registration.code === "KEY_LIMIT_REACHED"
        ? " The domain has 20 live keys: list them with `npx daywalker keys` and revoke unused ones with `npx daywalker revoke <keyId>`."
        : "";
    const message = `Registering the signing key failed (${registration.status || "network"}${registration.code ? ` ${registration.code}` : ""}): ${registration.error ?? "unknown error"}.${hint}`;
    if (registration.status === 0 || registration.status >= 500) throw new DaywalkerError(message, registration.status || undefined);
    throw new DaywalkerAuthError(message, 503, "KEY_REGISTRATION_FAILED");
  }

  /**
   * Resolves the signing key now instead of on the first request: loads it, or provisions and registers it
   * (see `keyStore`). Call it at startup to fail fast. Returns where the key came from and its id.
   */
  public async provisionSigningKey(): Promise<{ source: SignerSource; keyId: string } | null> {
    const active = await this.#getSigner();
    return active ? { source: active.source, keyId: active.signer.keyId } : null;
  }

  #dpopKey: Promise<DpopKey> | null = null;

  /** The client's DPoP key, generated on first use. Issued tokens are bound to it for this client's life. */
  #getDpopKey(): Promise<DpopKey> {
    return (this.#dpopKey ??= generateDpopKey());
  }

  async #getLoadedPreviousSigningKey(): Promise<SigningKey | null> {
    const raw = this.#config.previousSigningKey;
    if (!raw) return null;
    if (!this.#previousSigningKeyPromise) {
      this.#previousSigningKeyPromise = loadSigningKey(raw);
    }
    return this.#previousSigningKeyPromise;
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
    const authUrl = this.#config.authUrl;
    const url = new URL(path, authUrl);
    // Absolute URLs to other hosts would otherwise receive an access token and a valid signature.
    const authOrigin = new URL(authUrl).origin;
    if (url.origin !== authOrigin) {
      throw new DaywalkerError(`Refusing to send Daywalker credentials to ${url.origin}; fetch() only targets ${authOrigin}`);
    }
    const method = (init?.method ?? (init?.body !== undefined ? "POST" : "GET")).toUpperCase();
    const doFetch = this.#fetch;
    const { retry: _retry, timeoutMs: _timeoutMs, idempotencyKey, body: rawBody, signal: callerSignal, ...requestInit } = init ?? {};

    const retryOpts: RetryOptions = { ...this.#config.retry };
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
    const timeoutMs = init?.timeoutMs ?? this.#config.timeoutMs;
    const backoff = (n: number) => {
      let delayMs = initialDelayMs * Math.pow(backoffFactor, n - 1);
      if (jitter) delayMs = delayMs * (0.8 + Math.random() * 0.4);
      return Math.min(delayMs, maxDelayMs);
    };

    callerSignal?.throwIfAborted();
    const active = await this.#getSigner();
    const body = await prepareBody(rawBody, Boolean(active));
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
        headers.set("dpop", await createDpopProof(await this.#getDpopKey(), { method, url: url.toString(), accessToken }));
      }

      if (active) {
        // Signing never touches Authorization, so an explicit header is kept as given.
        const signedHeaders = await signRequest({
          method,
          path: url.pathname + url.search,
          authority: url.host,
          body: body.bytes,
          signer: active.signer,
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
        // Never served from or stored in an HTTP cache (Next.js patches fetch to cache by default).
        cache: "no-store",
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
        if (this.#tokens) this.#tokens = { ...this.#tokens, expiresAt: 0 };
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

  #cacheGet(key: string): { result: ValidateResult; jkt?: string } | undefined {
    const entry = this.#cache.get(key);
    if (!entry) return undefined;
    this.#cache.delete(key);
    if (entry.expiresAt <= Date.now()) return undefined;
    this.#cache.set(key, entry); // most recently used goes last
    return entry;
  }

  #cacheSet(key: string, result: ValidateResult, ttlMs: number, notAfterMs = Infinity, jkt?: string): void {
    const expiresAt = Math.min(Date.now() + ttlMs, notAfterMs);
    if (expiresAt <= Date.now()) return;
    this.#cache.delete(key);
    // Frozen, so nothing holding the entry can change what later callers get.
    this.#cache.set(key, Object.freeze({ result: deepFreeze(cloneResult(result)), expiresAt, jkt }));
    while (this.#cache.size > MAX_VALIDATION_CACHE_ENTRIES) {
      this.#cache.delete(this.#cache.keys().next().value as string);
    }
  }

  /**
   * Checks the DPoP proof a DPoP-bound (`cnf.jkt`) access token must come with. Run on every request, cached
   * token or not: a proof is single-use, so a copied token is worthless without the client's private key.
   */
  async #checkDpop(token: string, jkt: string, dpop: IncomingDpop | undefined): Promise<ValidateResult | null> {
    if (!dpop || typeof dpop.proof !== "string" || dpop.proof === "") {
      return {
        ok: false,
        error: "DPOP_REQUIRED",
        status: 401,
        message: "This access token is DPoP-bound: present it as `Authorization: DPoP <token>` with a DPoP proof",
      };
    }
    let url = dpop.url;
    if (this.#publicOrigin) {
      try {
        const u = new URL(dpop.url);
        url = `${this.#publicOrigin}${u.pathname}${u.search}`;
      } catch {
        url = "";
      }
    }
    const res = await verifyDpopProof({
      proof: dpop.proof,
      method: String(dpop.method ?? ""),
      url,
      accessToken: token,
      expectedJkt: jkt,
      replayStore: this.#dpopReplayStore,
    });
    return res.valid ? null : { ok: false, error: "INVALID_DPOP_PROOF", status: 401, message: res.error ?? "Invalid DPoP proof" };
  }

  /**
   * Validates an incoming token with memory caching and a discriminated union result.
   * - Access tokens (JWTs) are verified offline when Daywalker's public key is configured. A DPoP-bound
   *   token (`cnf.jkt`) is only accepted with a valid DPoP proof (`options.dpop`; the adapters pass it).
   * - Other tokens are validated online with `POST /api/v1/tokens/validate`, authenticated with this
   *   service's own DPoP-bound access token. The answer must name the expected service.
   * - A missing, oversized or malformed token is rejected (401) without calling Daywalker. A token is never
   *   replaced by this service's own credentials: use `validateServiceCredentials()` for that.
   * - Online validation fails closed: only a 2xx JSON answer with `valid: true` and a sane shape is accepted.
   *   Outages (network errors, timeouts, 5xx, malformed answers) return status 503 with error NETWORK_ERROR or
   *   SERVICE_UNAVAILABLE and are never cached. Each call gets its own copy of the (cached) result.
   */
  public async validateToken(
    tokenOrOptions?: string | (ValidateTokenOptions & { token?: string }),
    options?: ValidateTokenOptions
  ): Promise<ValidateResult> {
    const opts: ValidateTokenOptions & { token?: unknown } =
      typeof tokenOrOptions === "string" ? { ...options, token: tokenOrOptions } : { ...(tokenOrOptions ?? {}) };
    const token = opts.token;
    const forceRefresh = opts.forceRefresh === true;
    const offlineOnly = opts.offlineOnly === true;

    if (token === undefined || token === null || token === "") {
      return { ok: false, error: "INVALID_TOKEN", status: 401, message: "Missing token to validate" };
    }
    if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH || !TOKEN_PATTERN.test(token)) {
      // Never forwarded, hashed or cached: it can't be a Daywalker token.
      return { ok: false, error: "INVALID_TOKEN", status: 401, message: "Malformed token" };
    }
    const serviceSlug = String(opts.serviceSlug ?? this.#config.serviceSlug ?? "").toLowerCase();
    if (serviceSlug && !SERVICE_SLUG_PATTERN.test(serviceSlug)) {
      return { ok: false, error: "CONFIGURATION_ERROR", status: 500, message: "serviceSlug is not a valid Daywalker service slug" };
    }

    // Keyed by a hash so raw tokens are never held as cache keys.
    const cacheKey = `${serviceSlug || "default"}:${await sha256Base64Url(token)}`;
    const cached = forceRefresh ? undefined : this.#cacheGet(cacheKey);
    if (cached) {
      if (cached.jkt) {
        const failure = await this.#checkDpop(token, cached.jkt, opts.dpop);
        if (failure) return failure;
      }
      return cloneResult(cached.result);
    }

    // Offline verification of Daywalker access tokens: against the fetched JWKS with `jwks: "auto"`, else
    // (or while no key set can be obtained) against the configured public key.
    const isJwt = token.split(".").length === 3;
    const offlineKey = isJwt ? ((this.#config.jwks === "auto" ? await this.#jwksFor(jwtKid(token)) : null) ?? this.#config.daywalkerPublicKey) : null;
    if (offlineKey) {
      const jwtResult = await verifyJwtLease({
        token,
        publicKey: offlineKey,
        expectedServiceSlug: serviceSlug || undefined,
        expectedIssuer: this.#config.leaseIssuer ?? DEFAULT_ISSUER,
      });

      if (jwtResult.valid && jwtResult.payload) {
        const payload = jwtResult.payload;
        const cnf = payload.cnf as { jkt?: unknown } | undefined;
        const jkt = typeof cnf?.jkt === "string" ? cnf.jkt : undefined;
        if (jkt) {
          const failure = await this.#checkDpop(token, jkt, opts.dpop);
          if (failure) return failure;
        }
        const user = payload.user && typeof payload.user === "object" ? (payload.user as Record<string, unknown>) : {};
        const userId = typeof user.id === "string" ? user.id : typeof payload.sub === "string" ? payload.sub : undefined;
        const services = leaseServices(payload);
        const result: ValidateResult = {
          ok: true,
          data: {
            // Claims first: the verified fields below can't be overridden by a claim of the same name.
            ...payload,
            serviceSlug: serviceSlug || services[0] || "",
            tenantId: userId ?? "",
            userId,
            tokenId: typeof payload.jti === "string" ? payload.jti : undefined,
            rateLimit: { limit: 0, remaining: 0, reset: 0 },
            offlineVerified: true,
            services,
          },
        };

        if (this.#config.cacheTtlMs > 0) {
          // Never cache a token past its own expiry.
          this.#cacheSet(cacheKey, result, this.#config.cacheTtlMs, (payload.exp as number) * 1000, jkt);
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
    } else if (offlineOnly && isJwt && this.#config.jwks === "auto") {
      // Fail closed: no key set, no offline verdict.
      return {
        ok: false,
        error: "SERVICE_UNAVAILABLE",
        status: 503,
        message: "Offline verification failed: Daywalker's JWKS could not be fetched",
      };
    } else if (offlineOnly) {
      return {
        ok: false,
        error: "CONFIGURATION_ERROR",
        status: 500,
        message: "Offline verification requires DAYWALKER_PUBLIC_KEY or DAYWALKER_JWKS=auto and a Daywalker access token (JWT)",
      };
    }

    // Online verification, deduplicated across concurrent callers
    const inflightKey = `${cacheKey}`;
    const pending = this.#inflight.get(inflightKey);
    if (pending) return pending.then(cloneResult);
    const run = this.#validateOnline(token, serviceSlug, cacheKey).finally(() => {
      this.#inflight.delete(inflightKey);
    });
    this.#inflight.set(inflightKey, run);
    return run.then(cloneResult);
  }

  async #validateOnline(token: string, serviceSlug: string, cacheKey: string): Promise<ValidateResult> {
    const negTtl = this.#config.negativeCacheTtlMs;
    const fail = (result: Extract<ValidateResult, { ok: false }>): ValidateResult => {
      if (negTtl > 0 && result.error !== "RATE_LIMITED" && result.error !== "NETWORK_ERROR" && result.error !== "SERVICE_UNAVAILABLE") {
        this.#cacheSet(cacheKey, result, negTtl);
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
      const res = await this.fetch("/api/v1/tokens/validate", {
        method: "POST",
        body: { token },
        // Validation is read-only, so repeating it after a lost response is safe.
        retry: { retryNetworkErrors: this.#config.retry.retryNetworkErrors ?? true },
      });

      // A body that times out or is too large is an outage (thrown to NETWORK_ERROR below), never an answer.
      const text = await readText(res, this.#config.timeoutMs);
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
        const servedSlug = ((payloadData.serviceSlug ?? json.serviceSlug) as string | undefined)?.toLowerCase();
        const reported = (payloadData.services ?? json.services) as string[] | undefined;
        const services = Array.from(new Set((reported ?? (servedSlug ? [servedSlug] : [])).map((s) => s.toLowerCase())));
        if (services.length === 0 && !servedSlug) {
          return unavailable("Daywalker Auth returned a malformed validation result (no service named)");
        }
        // The token was validated for whichever service it shares with our credentials: make sure that
        // includes this one, so a token for a sibling service is never accepted here.
        if (serviceSlug && servedSlug !== serviceSlug && !services.includes(serviceSlug)) {
          return fail({
            ok: false,
            error: "SERVICE_NOT_GRANTED",
            status: 403,
            message: `This token is not valid for ${serviceSlug}`,
          });
        }
        const data: TokenPayload = {
          // Server fields first: the normalized fields below always win.
          ...payloadData,
          serviceSlug: serviceSlug || servedSlug || services[0],
          tenantId: (payloadData.tenantId || payloadData.userId || json.tenantId || json.userId || "") as string,
          rateLimit: (payloadData.rateLimit || json.rateLimit || { limit: 0, remaining: 0, reset: 0 }) as RateLimitWindow,
          rateLimitHourly: (payloadData.rateLimitHourly || json.rateLimitHourly) as RateLimitWindow | undefined,
          tokenId: (payloadData.tokenId || json.tokenId) as string | undefined,
          tokenName: (payloadData.tokenName || json.tokenName) as string | undefined,
          userId: (payloadData.userId || json.userId) as string | undefined,
          stage: (payloadData.stage || json.stage) as string | undefined,
          offlineVerified: false,
          services: services.length > 0 ? services : [servedSlug!],
        };

        const result: ValidateResult = { ok: true, data };
        if (this.#config.cacheTtlMs > 0) {
          this.#cacheSet(cacheKey, result, this.#config.cacheTtlMs);
        }
        return result;
      }

      // A 2xx is only a token verdict when it says so; anything else (HTML, `{}`, a captive portal) fails closed.
      if (res.ok && !(isObject && (json.valid === false || typeof json.error === "string"))) {
        return unavailable(`Daywalker Auth returned no validation result (HTTP ${res.status})`);
      }

      let error = "INVALID_TOKEN";
      const errMsg = String((typeof json.message === "string" && json.message) || (typeof json.error === "string" && json.error) || "").slice(0, 500);
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
      if (err instanceof DaywalkerAuthError || err instanceof DaywalkerError) return credentialFailure(err);
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
   * that the granted services include `serviceSlug` (default: the configured one; with none configured, at
   * least one service must be granted). Never use this to authenticate an incoming request. `forceRefresh`
   * starts a new client credentials grant.
   */
  public async validateServiceCredentials(options?: { serviceSlug?: string; forceRefresh?: boolean }): Promise<ValidateResult> {
    const serviceSlug = String(options?.serviceSlug ?? this.#config.serviceSlug ?? "").toLowerCase();
    if (serviceSlug && !SERVICE_SLUG_PATTERN.test(serviceSlug)) {
      return { ok: false, error: "CONFIGURATION_ERROR", status: 500, message: "serviceSlug is not a valid Daywalker service slug" };
    }
    let tokens: TokenSet;
    try {
      if (options?.forceRefresh === true) await this.getTokens();
      else await this.accessToken();
      tokens = this.#tokens!;
    } catch (err) {
      if (err instanceof DaywalkerAuthError || err instanceof DaywalkerError) return credentialFailure(err);
      return {
        ok: false,
        error: "NETWORK_ERROR",
        status: 503,
        message: redactSecrets(`Could not reach Daywalker Auth: ${(err as Error).message}`),
      };
    }
    if (serviceSlug ? !tokens.services.includes(serviceSlug) : tokens.services.length === 0) {
      return {
        ok: false,
        error: "SERVICE_NOT_GRANTED",
        status: 403,
        message: serviceSlug
          ? `The OAuth client credentials don't cover ${serviceSlug} (granted: ${tokens.services.join(", ") || "none"})`
          : "The OAuth client credentials were granted no service",
      };
    }
    const claims = decodeJwtClaims(tokens.accessToken);
    const user = claims.user && typeof claims.user === "object" ? (claims.user as Record<string, unknown>) : {};
    const userId = typeof user.id === "string" ? user.id : typeof claims.sub === "string" ? claims.sub : undefined;
    return {
      ok: true,
      data: {
        serviceSlug: serviceSlug || tokens.services[0],
        tenantId: userId ?? "",
        userId,
        rateLimit: { limit: 0, remaining: 0, reset: 0 },
        services: [...tokens.services],
        expiresAt: tokens.expiresAt,
      },
    };
  }

  /**
   * Throws DaywalkerAuthError or DaywalkerRateLimitError if token is invalid or rate limited.
   */
  public async requireValidToken(
    tokenOrOptions?: string | (ValidateTokenOptions & { token?: string }),
    options?: ValidateTokenOptions
  ): Promise<TokenPayload> {
    const result = await this.validateToken(tokenOrOptions, options);
    if (!result.ok) {
      if (result.status === 429) {
        throw new DaywalkerRateLimitError(result.message, result.retryAfter);
      }
      throw new DaywalkerAuthError(result.message, result.status, result.error);
    }
    return result.data;
  }

  #tokens: TokenSet | null = null;
  /** The key generation that was current when `#tokens` was requested. */
  #tokenGeneration = 0;
  #tokenFlight: Promise<TokenSet> | null = null;

  /**
   * POST /api/v1/oauth/token. The client credentials grant is the one request that carries the API key
   * (`Authorization: Bearer`, next to the RFC 9421 signature); a refresh is authenticated by its refresh
   * token and DPoP proof alone. The answer is checked before it is trusted: it must be a DPoP-bound token
   * pair of sane shape, and its lifetime is capped so a bad `expires_at` can't keep a token alive.
   */
  async #tokenRequest(body: Record<string, unknown>): Promise<TokenSet> {
    const headers: Record<string, string> = {};
    if (body.grant_type === "client_credentials") {
      if (!this.#config.apiKey) {
        throw new DaywalkerAuthError("DAYWALKER_API_KEY is not set: it is the client credential for the OAuth token endpoint", 500, "CONFIGURATION_ERROR");
      }
      if (!API_KEY_PATTERN.test(this.#config.apiKey)) {
        throw new DaywalkerAuthError("DAYWALKER_API_KEY contains characters an API key can't have", 500, "CONFIGURATION_ERROR");
      }
      headers.authorization = `Bearer ${this.#config.apiKey}`;
    }
    const res = await this.fetch(TOKEN_PATH, { method: "POST", body, headers });
    const json = await readJsonObject(res, this.#config.timeoutMs);
    const str = (v: unknown) => (typeof v === "string" ? v.slice(0, 500) : undefined);
    if (res.status !== 200) {
      throw new DaywalkerAuthError(
        redactSecrets(str(json.message) ?? str(json.error) ?? `Token request failed with HTTP ${res.status}`),
        res.status,
        str(json.code) ?? str(json.error)
      );
    }
    const malformed = (why: string) => new DaywalkerAuthError(`Daywalker Auth returned a malformed token response (${why})`, 502, "SERVICE_UNAVAILABLE");
    const isToken = (v: unknown): v is string => typeof v === "string" && v.length <= MAX_TOKEN_LENGTH && TOKEN_PATTERN.test(v);
    if (!isToken(json.access_token) || !isToken(json.refresh_token)) throw malformed("tokens missing or not tokens");
    // Every token Daywalker issues is sender-constrained; an unbound (bearer) token is refused, not used.
    if (typeof json.token_type !== "string" || json.token_type.toLowerCase() !== "dpop") throw malformed("token_type is not DPoP");
    const now = Math.floor(Date.now() / 1000);
    const expiresIn = Math.floor(Number(json.expires_in));
    if (!Number.isFinite(expiresIn) || expiresIn <= 0) throw malformed("expires_in is not a positive number");
    const lifetime = Math.min(expiresIn, MAX_ACCESS_TOKEN_LIFETIME_SECONDS);
    const expiresAtClaim = Number(json.expires_at);
    // Earliest of what the server says and what expires_in allows (a past expires_at means already expired).
    const expiresAt = Number.isFinite(expiresAtClaim) && json.expires_at !== undefined ? Math.min(Math.floor(expiresAtClaim), now + lifetime) : now + lifetime;
    const services = Array.isArray(json.services)
      ? Array.from(new Set(json.services.filter((x): x is string => typeof x === "string" && SERVICE_SLUG_PATTERN.test(x.toLowerCase())).map((x) => x.toLowerCase())))
      : [];
    const refreshExpiresIn = Math.max(0, Math.floor(Number(json.refresh_expires_in) || 0));
    this.#rememberLicenses(json, services);
    return deepFreeze({
      accessToken: json.access_token,
      refreshToken: json.refresh_token,
      tokenType: "DPoP",
      expiresAt,
      expiresIn: lifetime,
      refreshExpiresIn,
      scope: services.join(" "),
      services,
      jwksUri: typeof json.jwks_uri === "string" && json.jwks_uri.startsWith(`${this.#config.authUrl}/`) ? json.jwks_uri : undefined,
    });
  }

  /**
   * Client credentials grant (RFC 6749 §4.4): the signed request (API key + registered Ed25519 key) is
   * exchanged for a short-lived access token JWT and a rotating refresh token. By default the grant is
   * narrowed to the configured service slug(s) (least privilege); with none configured it covers every
   * service the credentials do. The tokens are remembered for `accessToken()`. The result is frozen.
   */
  public async getTokens(options: GetTokensOptions = {}): Promise<TokenSet> {
    const scope = options.scope ? parseServiceSlugs(options.scope) : this.#config.serviceSlugs.length > 0 ? [...this.#config.serviceSlugs] : undefined;
    if (options.scope && (!scope || scope.length === 0)) {
      throw new DaywalkerAuthError("getTokens: scope must list at least one service slug", 400, "INVALID_REQUEST");
    }
    if (scope && !scope.every((slug) => SERVICE_SLUG_PATTERN.test(slug))) {
      throw new DaywalkerAuthError("getTokens: scope must list Daywalker service slugs", 400, "INVALID_REQUEST");
    }
    if (options.expiresIn !== undefined && (!Number.isInteger(options.expiresIn) || options.expiresIn < 300 || options.expiresIn > 900)) {
      throw new DaywalkerAuthError("getTokens: expiresIn must be a whole number of seconds from 300 to 900", 400, "INVALID_REQUEST");
    }
    const generation = this.#keyGeneration;
    const tokens = await this.#tokenRequest({
      grant_type: "client_credentials",
      ...(scope ? { scope: scope.join(" ") } : {}),
      ...(options.expiresIn ? { expires_in: options.expiresIn } : {}),
    });
    this.#tokens = tokens;
    this.#tokenGeneration = generation;
    return tokens;
  }

  /**
   * Refresh token rotation: trades the refresh token for a NEW access token and a NEW refresh token; the
   * old refresh token stops working. Presenting an old one again revokes the whole session, so refreshes
   * are serialized per client and the new refresh token must replace the stored one.
   */
  public async refreshTokens(refreshToken?: string): Promise<TokenSet> {
    const token = refreshToken ?? this.#tokens?.refreshToken;
    if (!token) throw new DaywalkerAuthError("refreshTokens: no refresh token (call getTokens() first)", 400, "INVALID_REQUEST");
    if (typeof token !== "string" || token.length > MAX_TOKEN_LENGTH || !TOKEN_PATTERN.test(token)) {
      throw new DaywalkerAuthError("refreshTokens: malformed refresh token", 400, "INVALID_REQUEST");
    }
    const generation = this.#keyGeneration;
    const tokens = await this.#tokenRequest({ grant_type: "refresh_token", refresh_token: token });
    this.#tokens = tokens;
    this.#tokenGeneration = generation;
    return tokens;
  }

  /**
   * A valid access token, refreshing (or re-authenticating with the client credentials once the session
   * ended) when it is within 30 seconds of expiry. Concurrent callers share one request, so the single-use
   * refresh token is never presented twice.
   */
  public async accessToken(): Promise<string> {
    // Tokens from before the signing key was replaced belong to the old key's session: start a new one.
    const current = this.#tokenGeneration === this.#keyGeneration ? this.#tokens : null;
    if (current && current.expiresAt - 30 > Math.floor(Date.now() / 1000)) return current.accessToken;
    if (!this.#tokenFlight) {
      this.#tokenFlight = (async () => {
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
        this.#tokenFlight = null;
      });
    }
    return (await this.#tokenFlight).accessToken;
  }

  /** Licenses from the client credentials grant, by service slug. Kept out of TokenSet so they are never serialized. */
  #licenses = new Map<string, License>();

  #rememberLicenses(json: Record<string, unknown>, services: string[]): void {
    const found = new Map<string, License>();
    const add = (slug: string, key: unknown, expires: unknown) => {
      if (typeof key !== "string" || !/^[0-9a-f]{64}$/i.test(key) || typeof expires !== "string" || !Number.isFinite(Date.parse(expires))) return;
      if (!SERVICE_SLUG_PATTERN.test(slug)) return;
      found.set(slug, { serviceSlug: slug, licenseKey: key.toLowerCase(), expiresAt: expires });
    };
    if (json.licenses && typeof json.licenses === "object") {
      for (const [slug, v] of Object.entries(json.licenses as Record<string, any>)) add(slug.toLowerCase(), v?.licenseKey, v?.expiresAt);
    }
    const primary = services[0];
    if (primary && !found.has(primary)) add(primary, json.licenseKey ?? json.license_key, json.licenseExpiresAt ?? json.license_expires_at);
    // A refresh carries no licenses; keep the ones we hold until they expire.
    for (const [slug, license] of found) this.#licenses.set(slug, license);
  }

  #licenseCached(slug: string): License | null {
    const license = this.#licenses.get(slug);
    // A minute of margin so a key never expires between fetching it and using it.
    return license && Date.parse(license.expiresAt) - 60_000 > Date.now() ? license : null;
  }

  /**
   * The service's license key from Daywalker (issued with the client credentials grant, valid for one hour,
   * cached in memory until a minute before it expires). A revoked or suspended service gets no license: this
   * throws the DaywalkerAuthError Daywalker answered with (`SERVICE_REVOKED`, `SERVICE_SUSPENDED`,
   * `DOMAIN_REVOKED`, ...). `LICENSE_UNAVAILABLE` (403) means Daywalker granted the service without a license.
   * Never log the key.
   */
  public async getLicense(options: LicenseOptions = {}): Promise<License> {
    const slug = String(options.serviceSlug ?? this.#config.serviceSlug ?? "").toLowerCase();
    if (!slug || !SERVICE_SLUG_PATTERN.test(slug)) {
      throw new DaywalkerAuthError("getLicense: a valid serviceSlug is required", 500, "CONFIGURATION_ERROR");
    }
    if (options.forceRefresh !== true) {
      await this.accessToken();
      const cached = this.#licenseCached(slug);
      if (cached) return { ...cached };
    }
    const tokens = await this.getTokens();
    if (!tokens.services.includes(slug)) {
      throw new DaywalkerAuthError(`The OAuth client credentials don't cover ${slug}`, 403, "SERVICE_NOT_GRANTED");
    }
    const license = this.#licenseCached(slug);
    if (!license) throw new DaywalkerAuthError(`Daywalker Auth issued no license for ${slug}`, 403, "LICENSE_UNAVAILABLE");
    return { ...license };
  }

  /**
   * Fetches the config bundle (`POST /api/v1/services/:slug/bundle`) and opens it with the license key
   * (AES-256-GCM). The bundle can only be read by a client that got the license from Daywalker. At a window
   * rollover the key is refreshed once and the bundle opened again. Cached until shortly before it expires.
   */
  public async fetchBundle(options: LicenseOptions = {}): Promise<ConfigBundle> {
    const slug = String(options.serviceSlug ?? this.#config.serviceSlug ?? "").toLowerCase();
    if (!slug || !SERVICE_SLUG_PATTERN.test(slug)) {
      throw new DaywalkerAuthError("fetchBundle: a valid serviceSlug is required", 500, "CONFIGURATION_ERROR");
    }
    const cached = options.forceRefresh === true ? undefined : this.#bundles.get(slug);
    if (cached && Date.parse(cached.expiresAt) - 60_000 > Date.now()) return structuredClone(cached);
    let license = await this.getLicense(options);
    for (let attempt = 0; ; attempt++) {
      const res = await this.fetch(`/api/v1/services/${slug}/bundle`, { method: "POST", body: {} });
      const json = await readJsonObject(res, this.#config.timeoutMs);
      const str = (v: unknown) => (typeof v === "string" ? v.slice(0, 500) : undefined);
      if (res.status !== 200) {
        throw new DaywalkerAuthError(
          redactSecrets(str(json.message) ?? str(json.error) ?? `Bundle request failed with HTTP ${res.status}`),
          res.status,
          str(json.code) ?? str(json.error)
        );
      }
      const sealed = json.bundle as Record<string, unknown> | undefined;
      if (!sealed || typeof sealed.iv !== "string" || typeof sealed.tag !== "string" || typeof sealed.ciphertext !== "string") {
        throw new DaywalkerAuthError("Daywalker Auth returned a malformed bundle", 502, "SERVICE_UNAVAILABLE");
      }
      let bundle: ConfigBundle | null = null;
      try {
        bundle = await this.#openBundle(license.licenseKey, sealed as { iv: string; tag: string; ciphertext: string }, slug);
      } catch {
        bundle = null;
      }
      if (bundle) {
        this.#bundles.set(slug, bundle);
        return structuredClone(bundle);
      }
      if (attempt >= 1) throw new DaywalkerAuthError("The bundle could not be opened with the license key", 502, "BUNDLE_UNREADABLE");
      license = await this.getLicense({ ...options, forceRefresh: true });
    }
  }

  #bundles = new Map<string, ConfigBundle>();

  async #openBundle(licenseKey: string, sealed: { iv: string; tag: string; ciphertext: string }, slug: string): Promise<ConfigBundle> {
    const key = await webcrypto.importKey("raw", hexToBytes(licenseKey) as BufferSource, { name: "AES-GCM" }, false, ["decrypt"]);
    const tag = base64ToBytes(sealed.tag);
    const data = base64ToBytes(sealed.ciphertext);
    const joined = new Uint8Array(data.length + tag.length);
    joined.set(data);
    joined.set(tag, data.length);
    const plain = await webcrypto.decrypt({ name: "AES-GCM", iv: base64ToBytes(sealed.iv) as BufferSource, tagLength: 128 }, key, joined as BufferSource);
    const parsed = JSON.parse(utf8ToString(new Uint8Array(plain))) as ConfigBundle;
    if (!parsed || typeof parsed !== "object" || parsed.serviceSlug !== slug || typeof parsed.dataKeySalt !== "string") throw new Error("bad bundle");
    return deepFreeze(parsed);
  }

  /**
   * Fetches Daywalker's public JWKS (GET /.well-known/jwks.json) for offline lease verification.
   * Uses the configured `fetch`, sends no credentials, never follows redirects and times out after `timeoutMs`.
   */
  public fetchJwks(): Promise<{ keys: PublicJwk[] }> {
    return this.#fetchJwks();
  }

  async #fetchJwks(): Promise<{ keys: PublicJwk[] }> {
    const doFetch = this.#fetch;
    const { signal, cleanup } = attemptSignal(undefined, this.#config.timeoutMs);
    let res: Response;
    try {
      res = await doFetch(`${this.#config.authUrl.replace(/\/+$/, "")}/.well-known/jwks.json`, {
        headers: { Accept: "application/json" },
        redirect: "manual",
        cache: "no-store",
        signal,
      });
    } finally {
      cleanup();
    }
    if (isRedirect(res)) throw redirectError("/.well-known/jwks.json", res);
    if (!res.ok) throw new DaywalkerError(`Could not fetch JWKS (HTTP ${res.status})`, res.status);
    let json: { keys?: unknown } | null = null;
    try {
      json = JSON.parse(await readText(res, this.#config.timeoutMs));
    } catch (err) {
      if ((err as Error).name === "TimeoutError") throw err;
    }
    if (!json || typeof json !== "object" || !Array.isArray(json.keys)) {
      throw new DaywalkerError("JWKS response is not a JWK Set");
    }
    return { keys: json.keys as PublicJwk[] };
  }

  /**
   * The key set to verify a token naming `kid` with (`jwks: "auto"`), or null when none could be obtained.
   * The set is refetched once it is older than `JWKS_CACHE_TTL_MS`, or when it has no key with this `kid`
   * (Daywalker rotated its key), but never sooner than `JWKS_REFETCH_COOLDOWN_MS` after the last attempt.
   * Concurrent callers share one fetch. A failed fetch, or one with no usable key, keeps the previous set.
   * Only `${authUrl}/.well-known/jwks.json` is ever fetched: a `jwks_uri` from anywhere is not followed.
   */
  async #jwksFor(kid: string | undefined): Promise<PublicJwks | null> {
    const current = this.#jwks;
    const stale = !current || Date.now() - current.fetchedAt >= JWKS_CACHE_TTL_MS;
    const unknownKid = Boolean(current && kid !== undefined && !current.set.keys.some((k) => k.kid === kid));
    if ((stale || unknownKid) && (this.#jwksFlight || Date.now() - this.#jwksAttemptAt >= JWKS_REFETCH_COOLDOWN_MS)) {
      await this.#refreshJwks();
    }
    return this.#jwks?.set ?? null;
  }

  #refreshJwks(): Promise<void> {
    if (!this.#jwksFlight) {
      this.#jwksAttemptAt = Date.now();
      this.#jwksFlight = this.#fetchJwks()
        .then(
          ({ keys }) => {
            const usable = usableJwks(keys);
            if (usable.length > 0) this.#jwks = { set: deepFreeze({ keys: usable }), fetchedAt: Date.now() };
          },
          () => {
            // Keep the last good set; the cooldown spaces out the next attempt.
          }
        )
        .finally(() => {
          this.#jwksFlight = null;
        });
    }
    return this.#jwksFlight;
  }

  /**
   * The public JWK(s) configured for this service: the current signing key, then the previous one
   * (`previousSigningKey`) during a rotation, so requests from instances still on the old key keep verifying.
   */
  public async keys(): Promise<{ keys: PublicJwk[] }> {
    const active = await this.#getSigner();
    const keys = active?.publicJwk ? [active.publicJwk] : [];
    // A broken previous key must not take the current one offline; selfCheck() reports it.
    const previous = await this.#getLoadedPreviousSigningKey().catch(() => null);
    if (previous && !keys.some((k) => k.kid === previous.publicJwk.kid)) {
      keys.push(previous.publicJwk);
    }
    return { keys };
  }

  /**
   * Check configuration and verify signature readiness. Never provisions or registers a key: with a
   * `keyStore` it only reads what is stored and reports what first use would need.
   */
  public async selfCheck(): Promise<SelfCheckResult> {
    const problems = [...this.#config.problems];
    let keyId: string | null = null;
    let signing = false;

    if (this.#externalSigner) {
      signing = true;
      keyId = this.#externalSigner.keyId;
    } else if (this.#config.signingKey) {
      const signingKey = await this.#getLoadedSigningKey().catch((err) => {
        problems.push(`Signing key load error: ${(err as Error).message}`);
        return null;
      });
      signing = Boolean(signingKey);
      keyId = this.#config.keyId ?? signingKey?.publicJwk.kid ?? null;
    } else if (this.#config.ephemeralKey) {
      signing = Boolean(this.#config.domain);
      keyId = this.#ephemeral?.keyId ?? null;
      if (!this.#config.domain) problems.push("No public domain detected: set DAYWALKER_DOMAIN so the ephemeral signing key can be registered");
    } else if (this.#keyStore) {
      const store = this.#keyStore;
      try {
        const stored = await this.#loadStored(store);
        if (stored) {
          await this.#useStored(stored);
          keyId = stored.keyId;
          signing = true;
        } else if (!store.saveIfAbsent) {
          problems.push("The key store is read-only and holds no signing key: provision one with `npx daywalker init`");
        } else if (!this.#config.domain) {
          problems.push("No public domain detected: set DAYWALKER_DOMAIN so a signing key can be registered on first use");
        } else {
          signing = true; // provisioned and registered on first use
        }
      } catch (err) {
        problems.push(`Key store error: ${(err as Error).message}`);
      }
    } else {
      problems.push("No signing key: set DAYWALKER_SIGNING_KEY (npx daywalker init), a keyStore for auto-provisioning, or a signer");
    }
    await this.#getLoadedPreviousSigningKey().catch((err) => {
      problems.push(`Previous signing key load error: ${(err as Error).message}`);
    });

    return {
      ok: problems.length === 0,
      serviceSlug: this.#config.serviceSlug,
      serviceSlugs: this.#config.serviceSlugs,
      domain: this.#config.domain,
      signing,
      keyId,
      offlineVerificationReady: Boolean(this.#config.daywalkerPublicKey) || this.#config.jwks === "auto",
      problems,
    };
  }
}

// Methods can't be replaced on the class or (by assignment) on an instance, so code elsewhere in the process
// can't swap validateToken() for one that always says yes.
Object.freeze(Daywalker.prototype);
Object.freeze(Daywalker);

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
    // The shared default client can't be patched through the proxy either.
    set: () => false,
    defineProperty: () => false,
    deleteProperty: () => false,
    setPrototypeOf: () => false,
  }
);
