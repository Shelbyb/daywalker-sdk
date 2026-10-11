import type { PublicJwk, SigningKey, SignedHeaders, SignRequestParams, VerifySignatureParams, VerifySignatureResult } from "../types.js";
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToHex,
  stringToUtf8,
  utf8ToString,
  timingSafeEqualString,
} from "./encoding.js";
import { computeContentDigest } from "./digest.js";
import { loadPublicKey, loadSigningKey } from "./keys.js";
import { assertSecureUrl } from "../config.js";

export const SIGNATURE_VERSION = "rfc9421";
export const SIGNATURE_LABEL = "sig1";
export const SIGNATURE_ALG = "ed25519";
export const MAX_CLOCK_SKEW_SECONDS = 300;
export const SAFE_IDENTIFIER_PATTERN = /^[a-zA-Z0-9_\-\.]{1,128}$/;

/**
 * Normalizes HTTP request path per RFC 3986 to prevent path traversal & signature confusion.
 */
export function normalizePath(rawPath: string): string {
  if (!rawPath || !rawPath.trim()) return "/";
  let p = rawPath.trim();
  p = p.replace(/\/+/g, "/");
  try {
    const parsed = new URL(p, "http://localhost");
    return parsed.pathname + parsed.search;
  } catch {
    return p.startsWith("/") ? p : `/${p}`;
  }
}

/**
 * Validates that an identifier (keyId, serviceSlug, etc.) contains only safe alphanumeric/hyphen characters.
 */
export function assertSafeIdentifier(name: string, value: string): void {
  if (!value || typeof value !== "string" || value.length > 128 || !SAFE_IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`Invalid ${name}: must be 1-128 safe characters (alphanumeric, '_', '-', '.')`);
  }
}

/** Upper bound on remembered signatures; the oldest entries are evicted past this. */
export const REPLAY_CACHE_MAX_ENTRIES = 10_000;

/**
 * In-memory replay cache, keyed on keyid + decoded signature bytes (so re-encodings of the
 * same signature collide). Insertion-ordered, so eviction drops the oldest entries first.
 */
export class SignatureReplayCache {
  private seen = new Map<string, number>();

  constructor(private readonly maxEntries = REPLAY_CACHE_MAX_ENTRIES) {}

  public get size(): number {
    return this.seen.size;
  }

  /** True when the key was recorded and has not expired yet (a replay). */
  public has(key: string, now = Date.now()): boolean {
    const expiresAt = this.seen.get(key);
    return expiresAt !== undefined && expiresAt > now;
  }

  public record(key: string, ttlMs: number, now = Date.now()): void {
    this.seen.delete(key);
    this.seen.set(key, now + ttlMs);
    if (this.seen.size <= this.maxEntries) return;
    for (const [k, exp] of this.seen) {
      if (exp <= now) this.seen.delete(k);
    }
    while (this.seen.size > this.maxEntries) {
      this.seen.delete(this.seen.keys().next().value as string);
    }
  }

  public clear(): void {
    this.seen.clear();
  }
}

export const globalReplayCache = new SignatureReplayCache();

export type {
  SignedHeaders,
  SignRequestParams,
  VerifySignatureParams,
  VerifySignatureResult,
};

/**
 * Format the RFC 9421 Signature-Input parameters string.
 * Example: `("@method" "@path" "@authority" "content-digest");created=1791561600;keyid="...";alg="ed25519";nonce="..."`
 */
export function formatSignatureParams(params: {
  components?: string[];
  created: number;
  keyid: string;
  alg?: string;
  nonce?: string;
}): string {
  const components = params.components ?? ["@method", "@path", "@authority", "content-digest"];
  const componentsStr = components.map((c) => `"${c}"`).join(" ");
  let out = `(${componentsStr});created=${params.created};keyid="${params.keyid}";alg="${params.alg ?? SIGNATURE_ALG}"`;
  if (params.nonce) {
    out += `;nonce="${params.nonce}"`;
  }
  return out;
}

/**
 * Construct canonical RFC 9421 signature base string.
 */
export function createSignatureBase(params: {
  method: string;
  path: string;
  authority: string;
  contentDigest?: string | null;
  signatureParams: string;
  additionalComponents?: Record<string, string>;
}): string {
  const method = params.method.toUpperCase();
  const path = normalizePath(params.path);
  const authority = params.authority.toLowerCase();

  const lines = [
    `"@method": ${method}`,
    `"@path": ${path}`,
    `"@authority": ${authority}`,
  ];

  if (params.contentDigest !== undefined && params.contentDigest !== null) {
    lines.push(`"content-digest": ${params.contentDigest}`);
  }

  if (params.additionalComponents) {
    for (const [k, v] of Object.entries(params.additionalComponents)) {
      lines.push(`"${k.toLowerCase()}": ${v}`);
    }
  }

  lines.push(`"@signature-params": ${params.signatureParams}`);
  return lines.join("\n");
}

/**
 * Sign an outgoing HTTP request according to RFC 9421 + RFC 9530.
 */
export async function signRequest(params: SignRequestParams): Promise<SignedHeaders> {
  const signingKey = await loadSigningKey(params.key);
  const created = params.created ?? Math.floor(Date.now() / 1000);
  const keyid = params.keyid ?? signingKey.publicJwk.kid;
  const alg = params.alg ?? SIGNATURE_ALG;

  if (keyid) {
    assertSafeIdentifier("keyid", keyid);
  }

  const hasBody = params.body !== undefined && params.body !== null;
  const contentDigest = hasBody ? await computeContentDigest(params.body) : null;

  const components = ["@method", "@path", "@authority"];
  if (contentDigest !== null) {
    components.push("content-digest");
  }

  const signatureParams = formatSignatureParams({
    components,
    created,
    keyid,
    alg,
    nonce: params.nonce,
  });

  const signatureBase = createSignatureBase({
    method: params.method,
    path: params.path,
    authority: params.authority,
    contentDigest,
    signatureParams,
  });

  const signatureBuffer = await globalThis.crypto.subtle.sign(
    "Ed25519",
    signingKey.privateKey,
    stringToUtf8(signatureBase) as unknown as BufferSource
  );

  const signatureBase64 = bytesToBase64(new Uint8Array(signatureBuffer));

  const headers: SignedHeaders = {
    "Signature-Input": `${SIGNATURE_LABEL}=${signatureParams}`,
    Signature: `${SIGNATURE_LABEL}=:${signatureBase64}:`,
  };

  if (contentDigest !== null) {
    headers["Content-Digest"] = contentDigest;
  }

  if (params.apiKey) {
    headers["Authorization"] = `Bearer ${params.apiKey}`;
  }

  return headers;
}

/**
 * Verify an incoming RFC 9421 HTTP Message Signature.
 */
export async function verifyRequestSignature(
  params: VerifySignatureParams
): Promise<VerifySignatureResult> {
  const getHeader = (name: string): string | undefined => {
    if (params.headers instanceof Headers) {
      return params.headers.get(name) ?? undefined;
    }
    const lower = name.toLowerCase();
    for (const [k, v] of Object.entries(params.headers)) {
      if (k.toLowerCase() === lower && v !== undefined) return v;
    }
    return undefined;
  };

  const sigInputHeader = getHeader("Signature-Input");
  const signatureHeader = getHeader("Signature");
  const contentDigestHeader = getHeader("Content-Digest");

  if (!sigInputHeader || !signatureHeader) {
    return { valid: false, error: "Missing Signature-Input or Signature header" };
  }

  const sigInputMatch = sigInputHeader.match(new RegExp(`(?:^|,\\s*)${SIGNATURE_LABEL}=([^,]+)`));
  if (!sigInputMatch) {
    return { valid: false, error: `Signature-Input header does not contain ${SIGNATURE_LABEL}` };
  }
  const signatureParams = sigInputMatch[1].trim();

  // Validate parameters and check for component duplicates
  const coveredComponentsMatch = signatureParams.match(/^\(([^)]*)\)/);
  if (!coveredComponentsMatch) {
    return { valid: false, error: "Signature-Input missing covered components list" };
  }
  const rawComponents = coveredComponentsMatch[1].trim().split(/\s+/).filter(Boolean);
  const seenComponents = new Set<string>();
  for (const c of rawComponents) {
    if (seenComponents.has(c)) {
      return { valid: false, error: `Duplicate covered component in Signature-Input: ${c}` };
    }
    seenComponents.add(c);
  }

  // RFC 8941 byte sequence (`:base64:`), standard alphabet with padding only, so each signature
  // has exactly one accepted encoding.
  const sigMatch = signatureHeader.match(new RegExp(`(?:^|,\\s*)${SIGNATURE_LABEL}=:([A-Za-z0-9+/]*={0,2}):(?=\\s*(?:,|$))`));
  if (!sigMatch || sigMatch[1].length % 4 !== 0) {
    return { valid: false, error: `Signature header does not contain valid ${SIGNATURE_LABEL} byte sequence` };
  }
  const signatureBytes = base64ToBytes(sigMatch[1]);
  if (bytesToBase64(signatureBytes) !== sigMatch[1]) {
    return { valid: false, error: `Signature header does not contain valid ${SIGNATURE_LABEL} byte sequence` };
  }

  const createdMatch = signatureParams.match(/created=(\d+)/);
  if (!createdMatch) {
    return { valid: false, error: "Signature-Input missing created timestamp" };
  }
  const created = parseInt(createdMatch[1], 10);
  const now = params.currentTime ?? Math.floor(Date.now() / 1000);
  const maxSkew = params.maxClockSkewSeconds ?? MAX_CLOCK_SKEW_SECONDS;

  if (Math.abs(now - created) > maxSkew) {
    return { valid: false, error: `Signature timestamp expired or clock skew too large (created=${created}, now=${now})` };
  }

  const keyidMatch = signatureParams.match(/keyid="([^"]+)"/);
  const keyid = keyidMatch ? keyidMatch[1] : undefined;
  if (keyid) {
    try {
      assertSafeIdentifier("keyid", keyid);
    } catch (e) {
      return { valid: false, error: (e as Error).message };
    }
  }

  // Entries must outlive the whole acceptance window (created ± maxSkew).
  const replayKey = `${keyid ?? ""}:${bytesToHex(signatureBytes)}`;
  const replayTtlMs = 2 * Math.max(maxSkew, 1) * 1000;
  if (params.replayCheck !== false && globalReplayCache.has(replayKey)) {
    return { valid: false, error: "Replay detected: request signature was already presented" };
  }

  const algMatch = signatureParams.match(/alg="([^"]+)"/);
  const alg = algMatch ? algMatch[1] : undefined;
  if (alg && alg.toLowerCase() !== "ed25519" && alg.toLowerCase() !== "eddsa") {
    return { valid: false, error: `Unsupported signature algorithm: ${alg}` };
  }

  if (signatureParams.includes('"content-digest"')) {
    if (!contentDigestHeader) {
      return { valid: false, error: "Signature covers content-digest but Content-Digest header is missing" };
    }
    const computedDigest = await computeContentDigest(params.body ?? "");
    if (!computedDigest || !timingSafeEqualString(contentDigestHeader.trim(), computedDigest)) {
      return { valid: false, error: `Content-Digest mismatch: expected ${computedDigest}, got ${contentDigestHeader}` };
    }
  }

  const signatureBase = createSignatureBase({
    method: params.method,
    path: params.path,
    authority: params.authority,
    contentDigest: signatureParams.includes('"content-digest"') ? contentDigestHeader?.trim() : null,
    signatureParams,
  });

  try {
    const { publicKey } = await loadPublicKey(params.publicKey);

    const isValid = await globalThis.crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signatureBytes as unknown as BufferSource,
      stringToUtf8(signatureBase) as unknown as BufferSource
    );

    if (!isValid) {
      return { valid: false, error: "Cryptographic signature verification failed" };
    }

    // Record only verified signatures; re-check synchronously in case a concurrent copy won.
    if (params.replayCheck !== false) {
      if (globalReplayCache.has(replayKey)) {
        return { valid: false, error: "Replay detected: request signature was already presented" };
      }
      globalReplayCache.record(replayKey, replayTtlMs);
    }

    return { valid: true, keyid };
  } catch (err) {
    return { valid: false, error: `Verification error: ${(err as Error).message}` };
  }
}

/** Clock skew tolerated on JWT lease `exp` / `nbf`. */
export const JWT_CLOCK_SKEW_SECONDS = 60;

/**
 * Zero-egress offline verification for asymmetric JWT token leases.
 * Requires a numeric `exp` and an audience (`aud` or `serviceSlug`) equal to `expectedServiceSlug`;
 * a verifier without an expected slug rejects every lease. `iss` is checked when `expectedIssuer` is set.
 */
export async function verifyJwtLease(params: {
  token: string;
  publicKey: string | PublicJwk | CryptoKey;
  expectedServiceSlug?: string;
  expectedIssuer?: string;
  currentTime?: number;
  clockSkewSeconds?: number;
}): Promise<{ valid: boolean; payload?: Record<string, unknown>; error?: string }> {
  try {
    const parts = params.token.trim().split(".");
    if (parts.length !== 3) {
      return { valid: false, error: "Token is not a valid 3-part JWT" };
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    const headerJson = utf8ToString(base64UrlToBytes(headerB64));
    const payloadJson = utf8ToString(base64UrlToBytes(payloadB64));

    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);
    if (!header || typeof header !== "object" || !payload || typeof payload !== "object" || Array.isArray(payload)) {
      return { valid: false, error: "JWT header and payload must be JSON objects" };
    }

    if (header.alg !== "EdDSA" && header.alg !== "ed25519") {
      return { valid: false, error: `Unsupported JWT alg: ${header.alg}` };
    }
    if (header.typ !== undefined && String(header.typ).toUpperCase() !== "JWT") {
      return { valid: false, error: `Unsupported JWT typ: ${header.typ}` };
    }

    const { publicKey } = await loadPublicKey(params.publicKey);
    const signedData = stringToUtf8(`${headerB64}.${payloadB64}`);
    const signatureBytes = base64UrlToBytes(signatureB64);

    const isValid = await globalThis.crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signatureBytes as unknown as BufferSource,
      signedData as unknown as BufferSource
    );

    if (!isValid) {
      return { valid: false, error: "JWT signature verification failed" };
    }

    const now = params.currentTime ?? Math.floor(Date.now() / 1000);
    const skew = Math.max(0, Math.min(params.clockSkewSeconds ?? JWT_CLOCK_SKEW_SECONDS, 300));
    if (typeof payload.exp !== "number" || !Number.isFinite(payload.exp)) {
      return { valid: false, error: "JWT token lease has no numeric exp claim" };
    }
    if (payload.exp + skew <= now) {
      return { valid: false, error: "JWT token lease has expired" };
    }
    if (payload.nbf !== undefined && (typeof payload.nbf !== "number" || payload.nbf > now + skew)) {
      return { valid: false, error: "JWT token lease not active yet" };
    }

    const expected = params.expectedServiceSlug?.trim().toLowerCase();
    if (!expected) {
      return { valid: false, error: "JWT audience cannot be checked: no expected service slug is configured" };
    }
    const audiences: string[] = [];
    if (payload.serviceSlug !== undefined) audiences.push(String(payload.serviceSlug));
    if (Array.isArray(payload.aud)) audiences.push(...payload.aud.map(String));
    else if (payload.aud !== undefined) audiences.push(String(payload.aud));
    if (audiences.length === 0) {
      return { valid: false, error: "JWT token lease has no aud or serviceSlug claim" };
    }
    const serviceSlugOk = payload.serviceSlug === undefined || String(payload.serviceSlug).toLowerCase() === expected;
    const audOk =
      payload.aud === undefined ||
      (Array.isArray(payload.aud) ? payload.aud : [payload.aud]).some((a: unknown) => String(a).toLowerCase() === expected);
    if (!serviceSlugOk || !audOk) {
      return {
        valid: false,
        error: `JWT audience mismatch: expected ${expected}, got ${audiences.join(", ").toLowerCase()}`,
      };
    }

    if (params.expectedIssuer && payload.iss !== params.expectedIssuer) {
      return { valid: false, error: `JWT issuer mismatch: expected ${params.expectedIssuer}, got ${payload.iss ?? "(none)"}` };
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: `Failed to verify JWT lease: ${(err as Error).message}` };
  }
}

/**
 * Register public key directly with Daywalker Auth via POST /api/v1/keys/register (Push Architecture).
 */
export async function registerPublicKey(params: {
  authUrl?: string;
  apiKey: string;
  serviceSlug?: string;
  domain?: string | null;
  publicJwk: PublicJwk;
  fetchFn?: typeof fetch;
}): Promise<{ ok: boolean; status: number; error?: string }> {
  const authUrl = (params.authUrl ?? "https://auth.daywalker.dev").replace(/\/+$/, "");
  try {
    assertSecureUrl("authUrl", authUrl);
  } catch (err) {
    return { ok: false, status: 0, error: (err as Error).message };
  }
  const registerUrl = `${authUrl}/api/v1/keys/register`;
  const doFetch = params.fetchFn ?? globalThis.fetch;

  if (!params.domain) {
    return { ok: false, status: 400, error: "domain is required to register a key (set --domain or DAYWALKER_DOMAIN)" };
  }

  try {
    const res = await doFetch(registerUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${params.apiKey}`,
      },
      body: JSON.stringify({
        keyId: params.publicJwk.kid,
        domain: params.domain,
        publicKey: params.publicJwk,
      }),
    });

    if (res.ok) {
      return { ok: true, status: res.status };
    }

    const data = (await res.json().catch(() => ({}))) as { message?: string; error?: string };
    return {
      ok: false,
      status: res.status,
      error: data.message || data.error || `HTTP ${res.status}`,
    };
  } catch (err) {
    return {
      ok: false,
      status: 0,
      error: (err as Error).message,
    };
  }
}
