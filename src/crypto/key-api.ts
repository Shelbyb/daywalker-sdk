import { webcrypto } from "./webcrypto.js";
import type { PublicJwk } from "../types.js";
import { redactSecrets } from "./encoding.js";
import { API_KEY_PATTERN, SAFE_IDENTIFIER_PATTERN, SERVICE_SLUG_PATTERN, assertSafeIdentifier } from "./signatures.js";
import { assertSecureUrl, parseServiceSlugs, publicHostname } from "../config.js";

/**
 * Daywalker's signing-key lifecycle API (`/api/v1/keys*`), authenticated with the API key as
 * `Authorization: Bearer`. Every call goes only to `authUrl`: redirects are refused (never followed with the
 * key), requests time out after 10s, nothing is cached, inputs are validated first and answers are bounded.
 */

/** Per-attempt timeout for key API calls. */
const KEY_API_TIMEOUT_MS = 10_000;
/** Largest key API answer read. */
const MAX_KEY_API_RESPONSE_BYTES = 262_144;

/** Daywalker's `instanceId` format: one key slot per (domain, instanceId). */
export const INSTANCE_ID_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
/** Key lifetime bounds Daywalker accepts for `ttlSeconds` (1 hour to 30 days). */
export const MIN_KEY_TTL_SECONDS = 3_600;
export const MAX_KEY_TTL_SECONDS = 2_592_000;

/**
 * The instance slot the SDK registers a key in: one slot per key (`dw-<keyId>`), so registering a key never
 * demotes another one (Daywalker moves the previous key of the same slot to ROTATING, then revokes it).
 */
export function keySlotFor(keyId: string): string {
  const slot = `dw-${keyId}`.slice(0, 64);
  if (!INSTANCE_ID_PATTERN.test(slot)) throw new Error("keyId can't be used as an instance slot");
  return slot;
}

/** A signing key as Daywalker reports it. */
export interface SigningKeyRecord {
  id?: string;
  keyId: string;
  domain: string;
  status: "ACTIVE" | "ROTATING" | "REVOKED";
  instanceId: string | null;
  /** Unix seconds, or null when the key doesn't expire. */
  expiresAt: number | null;
  createdAt: number | null;
  lastUsedAt: number | null;
}

export interface KeyApiResult {
  ok: boolean;
  status: number;
  /** Daywalker's error code (`KEY_LIMIT_REACHED`, `KEY_ID_CONFLICT`, `domain_not_allowed`, …). */
  code?: string;
  error?: string;
}

interface KeyApiBase {
  authUrl?: string;
  apiKey: string;
  fetchFn?: typeof fetch;
}

const seconds = (v: unknown): number | null => {
  if (typeof v !== "string" && typeof v !== "number") return null;
  const t = typeof v === "number" ? v * 1000 : Date.parse(v);
  return Number.isFinite(t) ? Math.floor(t / 1000) : null;
};

/** A record from Daywalker, checked and normalized, or null when it isn't one. */
function parseKeyRecord(value: unknown): SigningKeyRecord | null {
  if (!value || typeof value !== "object" || Array.isArray(value)) return null;
  const v = value as Record<string, unknown>;
  if (typeof v.keyId !== "string" || !SAFE_IDENTIFIER_PATTERN.test(v.keyId)) return null;
  if (typeof v.domain !== "string" || !publicHostname(v.domain)) return null;
  if (v.status !== "ACTIVE" && v.status !== "ROTATING" && v.status !== "REVOKED") return null;
  const instanceId = typeof v.instanceId === "string" && INSTANCE_ID_PATTERN.test(v.instanceId) ? v.instanceId : null;
  return Object.freeze({
    ...(typeof v.id === "string" ? { id: v.id } : {}),
    keyId: v.keyId,
    domain: v.domain.toLowerCase(),
    status: v.status,
    instanceId,
    expiresAt: seconds(v.expiresAt),
    createdAt: seconds(v.createdAt),
    lastUsedAt: seconds(v.lastUsedAt),
  });
}

/** Validates the shared inputs; returns an error result, or the base URL. */
function prepare(params: KeyApiBase): KeyApiResult | { base: string; doFetch: typeof fetch } {
  const base = (params.authUrl ?? "https://auth.daywalker.dev").replace(/\/+$/, "");
  try {
    assertSecureUrl("authUrl", base);
  } catch (err) {
    return { ok: false, status: 0, error: (err as Error).message };
  }
  if (typeof params.apiKey !== "string" || !API_KEY_PATTERN.test(params.apiKey)) {
    return { ok: false, status: 400, error: "apiKey is missing or contains characters an API key can't have" };
  }
  return { base, doFetch: params.fetchFn ?? globalThis.fetch };
}

/** One key API call: no redirects, no cache, a timeout, a bounded JSON answer. */
async function call(
  doFetch: typeof fetch,
  url: string,
  apiKey: string,
  init: { method: string; body?: unknown }
): Promise<{ status: number; json: Record<string, unknown> } | KeyApiResult> {
  try {
    const res = await doFetch(url, {
      method: init.method,
      headers: {
        ...(init.body !== undefined ? { "Content-Type": "application/json" } : {}),
        Accept: "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      ...(init.body !== undefined ? { body: JSON.stringify(init.body) } : {}),
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(KEY_API_TIMEOUT_MS),
    });
    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      res.body?.cancel().catch(() => {});
      return { ok: false, status: res.status, error: "Daywalker Auth answered with a redirect; refusing to follow it with the API key" };
    }
    const text = await res.text();
    if (text.length > MAX_KEY_API_RESPONSE_BYTES) return { ok: false, status: res.status, error: "Daywalker Auth answer is too large" };
    let parsed: unknown = {};
    try {
      parsed = text ? JSON.parse(text) : {};
    } catch {
      parsed = {};
    }
    const json = parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
    return { status: res.status, json };
  } catch (err) {
    return { ok: false, status: 0, error: redactSecrets((err as Error).message) };
  }
}

function failure(status: number, json: Record<string, unknown>): KeyApiResult {
  const code = typeof json.error === "string" ? json.error.slice(0, 64) : typeof json.code === "string" ? json.code.slice(0, 64) : undefined;
  const message = typeof json.message === "string" ? json.message : code ?? `HTTP ${status}`;
  return { ok: false, status, code, error: redactSecrets(message.slice(0, 500)) };
}

/**
 * Register public key directly with Daywalker Auth via POST /api/v1/keys/register (Push Architecture).
 * Re-registering the same key is idempotent (200). `instanceId` puts the key in a slot: registering a new key
 * in an occupied slot moves the old one to ROTATING for 10 minutes, then revokes it; without `instanceId`
 * the same happens to every other slot-less key of the domain, so the SDK always passes one (`keySlotFor`).
 * `ttlSeconds` (1 hour to 30 days) or `expiresAt` make the key expire. Errors carry Daywalker's `code`
 * (`KEY_LIMIT_REACHED`: 20 live keys per domain; `KEY_ID_CONFLICT`; `domain_not_allowed`).
 */
export async function registerPublicKey(
  params: KeyApiBase & {
    serviceSlug?: string;
    domain?: string | null;
    publicJwk: PublicJwk;
    instanceId?: string;
    ttlSeconds?: number;
    expiresAt?: Date;
  }
): Promise<KeyApiResult & { key?: SigningKeyRecord }> {
  const prepared = prepare(params);
  if ("ok" in prepared) return prepared;

  if (!params.domain) {
    return { ok: false, status: 400, error: "domain is required to register a key (set --domain or DAYWALKER_DOMAIN)" };
  }
  const domain = publicHostname(params.domain);
  if (!domain) {
    return { ok: false, status: 400, error: `domain (${params.domain}) is not a public hostname` };
  }
  const slugs = params.serviceSlug ? parseServiceSlugs(params.serviceSlug) : [];
  if (!slugs.every((slug) => SERVICE_SLUG_PATTERN.test(slug))) {
    return { ok: false, status: 400, error: "serviceSlug must be Daywalker service slug(s)" };
  }
  const jwk = params.publicJwk;
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string" || !/^[A-Za-z0-9_-]{43}$/.test(jwk.x) || "d" in jwk) {
    return { ok: false, status: 400, error: "publicJwk must be an Ed25519 public JWK (never a private key)" };
  }
  try {
    assertSafeIdentifier("keyId", jwk.kid);
  } catch (err) {
    return { ok: false, status: 400, error: (err as Error).message };
  }
  if (params.instanceId !== undefined && !INSTANCE_ID_PATTERN.test(params.instanceId)) {
    return { ok: false, status: 400, error: "instanceId must be 1-64 of A-Z a-z 0-9 . _ -" };
  }
  if (params.ttlSeconds !== undefined && (!Number.isInteger(params.ttlSeconds) || params.ttlSeconds < MIN_KEY_TTL_SECONDS || params.ttlSeconds > MAX_KEY_TTL_SECONDS)) {
    return { ok: false, status: 400, error: `ttlSeconds must be a whole number from ${MIN_KEY_TTL_SECONDS} to ${MAX_KEY_TTL_SECONDS}` };
  }
  if (params.expiresAt !== undefined && (!(params.expiresAt instanceof Date) || !(params.expiresAt.getTime() > Date.now()))) {
    return { ok: false, status: 400, error: "expiresAt must be a date in the future" };
  }

  const res = await call(prepared.doFetch, `${prepared.base}/api/v1/keys/register`, params.apiKey, {
    method: "POST",
    body: {
      keyId: jwk.kid,
      domain,
      publicKey: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: jwk.kid, use: "sig", alg: "EdDSA" },
      // Lets Daywalker refuse right away when the API key doesn't cover the service(s); a comma-separated list is fine
      ...(slugs.length > 0 ? { serviceSlug: slugs.join(",") } : {}),
      ...(params.instanceId ? { instanceId: params.instanceId } : {}),
      ...(params.ttlSeconds ? { ttlSeconds: params.ttlSeconds } : {}),
      ...(params.expiresAt ? { expiresAt: params.expiresAt.toISOString() } : {}),
    },
  });
  if ("ok" in res) return res;
  if (res.status !== 200 && res.status !== 201) return failure(res.status, res.json);
  const key = parseKeyRecord(res.json);
  // An answer for another key or domain is not a registration of this one.
  if (key && (key.keyId !== jwk.kid || key.domain !== domain)) {
    return { ok: false, status: 502, error: "Daywalker Auth answered with a different key or domain" };
  }
  return { ok: true, status: res.status, ...(key ? { key } : {}) };
}

/** Lists the signing keys registered for `domain` (GET /api/v1/keys), newest first. */
export async function listSigningKeys(params: KeyApiBase & { domain: string }): Promise<KeyApiResult & { keys?: SigningKeyRecord[] }> {
  const prepared = prepare(params);
  if ("ok" in prepared) return prepared;
  const domain = publicHostname(params.domain);
  if (!domain) return { ok: false, status: 400, error: `domain (${params.domain}) is not a public hostname` };
  const res = await call(prepared.doFetch, `${prepared.base}/api/v1/keys?domain=${encodeURIComponent(domain)}`, params.apiKey, { method: "GET" });
  if ("ok" in res) return res;
  if (res.status !== 200) return failure(res.status, res.json);
  if (!Array.isArray(res.json.keys)) return { ok: false, status: 502, error: "Daywalker Auth returned no key list" };
  const keys = res.json.keys.map(parseKeyRecord).filter((k): k is SigningKeyRecord => k !== null && k.domain === domain);
  return { ok: true, status: 200, keys };
}

/**
 * Revokes a signing key now (DELETE /api/v1/keys/{keyId}). Daywalker also ends every OAuth session that was
 * authenticated with it. Revoking a key that is already revoked succeeds; an unknown key is 404 `key_not_found`.
 */
export async function revokeSigningKey(params: KeyApiBase & { keyId: string }): Promise<KeyApiResult> {
  const prepared = prepare(params);
  if ("ok" in prepared) return prepared;
  if (typeof params.keyId !== "string" || !SAFE_IDENTIFIER_PATTERN.test(params.keyId)) {
    return { ok: false, status: 400, error: "keyId must be 1-128 safe characters" };
  }
  const res = await call(prepared.doFetch, `${prepared.base}/api/v1/keys/${encodeURIComponent(params.keyId)}`, params.apiKey, { method: "DELETE" });
  if ("ok" in res) return res;
  return res.status === 200 ? { ok: true, status: 200 } : failure(res.status, res.json);
}

/** A random instance slot for a process (`dw-i-<random>`), for keys that live only as long as it does. */
export function randomInstanceId(): string {
  const bytes = webcrypto.getRandomValues(new Uint8Array(12));
  return `dw-i-${Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("")}`;
}
