import type { PublicJwk, SigningKey, SignedHeaders, SignRequestParams, VerifySignatureParams, VerifySignatureResult } from "../types.js";
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  stringToUtf8,
  utf8ToString,
  timingSafeEqualString,
} from "./encoding.js";
import { computeContentDigest } from "./digest.js";
import { loadPublicKey, loadSigningKey } from "./keys.js";

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

/**
 * In-memory LRU / sliding cache for nonces / signature replay protection.
 */
class SignatureReplayCache {
  private seen = new Map<string, number>();
  private readonly ttlMs: number;

  constructor(ttlSeconds = 360) {
    this.ttlMs = ttlSeconds * 1000;
  }

  public checkAndRecord(signatureId: string): boolean {
    const now = Date.now();
    if (this.seen.size > 5000) {
      for (const [k, exp] of this.seen.entries()) {
        if (exp <= now) this.seen.delete(k);
      }
    }
    const expiresAt = this.seen.get(signatureId);
    if (expiresAt && expiresAt > now) {
      return false; // Replay detected
    }
    this.seen.set(signatureId, now + this.ttlMs);
    return true;
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

  const sigMatch = signatureHeader.match(new RegExp(`(?:^|,\\s*)${SIGNATURE_LABEL}=:([A-Za-z0-9+/=_-]+):`));
  if (!sigMatch) {
    return { valid: false, error: `Signature header does not contain valid ${SIGNATURE_LABEL} byte sequence` };
  }
  const signatureBase64 = sigMatch[1].trim();

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

  if (params.replayCheck !== false) {
    const replayKey = `${signatureBase64}:${created}`;
    if (!globalReplayCache.checkAndRecord(replayKey)) {
      return { valid: false, error: "Replay detected: request signature was already presented" };
    }
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
    const signatureBytes = signatureBase64.includes("-") || signatureBase64.includes("_")
      ? base64UrlToBytes(signatureBase64)
      : base64ToBytes(signatureBase64);

    const isValid = await globalThis.crypto.subtle.verify(
      "Ed25519",
      publicKey,
      signatureBytes as unknown as BufferSource,
      stringToUtf8(signatureBase) as unknown as BufferSource
    );

    if (!isValid) {
      return { valid: false, error: "Cryptographic signature verification failed" };
    }

    return { valid: true, keyid };
  } catch (err) {
    return { valid: false, error: `Verification error: ${(err as Error).message}` };
  }
}

/**
 * Zero-egress offline verification for asymmetric JWT token leases.
 */
export async function verifyJwtLease(params: {
  token: string;
  publicKey: string | PublicJwk | CryptoKey;
  expectedServiceSlug?: string;
  currentTime?: number;
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

    if (header.alg !== "EdDSA" && header.alg !== "ed25519") {
      return { valid: false, error: `Unsupported JWT alg: ${header.alg}` };
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
    if (payload.exp && typeof payload.exp === "number" && payload.exp < now) {
      return { valid: false, error: "JWT token lease has expired" };
    }
    if (payload.nbf && typeof payload.nbf === "number" && payload.nbf > now + 60) {
      return { valid: false, error: "JWT token lease not active yet" };
    }

    if (params.expectedServiceSlug) {
      const tokenSlug = (payload.serviceSlug || payload.aud || "").toLowerCase();
      if (tokenSlug && tokenSlug !== params.expectedServiceSlug.toLowerCase()) {
        return {
          valid: false,
          error: `JWT audience mismatch: expected ${params.expectedServiceSlug}, got ${tokenSlug}`,
        };
      }
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
  const registerUrl = `${authUrl}/api/v1/keys/register`;
  const doFetch = params.fetchFn ?? globalThis.fetch;

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
        domain: params.domain ?? undefined,
        serviceSlug: params.serviceSlug ?? undefined,
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
