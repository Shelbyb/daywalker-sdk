import { webcrypto } from "./webcrypto.js";
import { base64UrlToBytesStrict, bytesToBase64Url, stringToUtf8, timingSafeEqualString, utf8ToString } from "./encoding.js";
import { SignatureReplayCache, type ReplayStore } from "./signatures.js";
import { sha256Base64Url } from "./digest.js";

/**
 * DPoP (RFC 9449) proof-of-possession. Daywalker binds every access and refresh token to a client key and
 * requires a fresh proof on each token request, refresh and validate call.
 */
export interface DpopKey {
  privateKey: CryptoKey;
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
}

/**
 * A new in-memory Ed25519 DPoP key. Tokens are bound to it, so keep it for the life of the session. The private
 * key is non-extractable: nothing (including this SDK) can export it, so a bound token can't be moved elsewhere.
 */
export async function generateDpopKey(): Promise<DpopKey> {
  const pair = (await webcrypto.generateKey({ name: "Ed25519" } as any, false, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await webcrypto.exportKey("jwk", pair.publicKey)) as { x: string };
  return { privateKey: pair.privateKey, publicJwk: { kty: "OKP", crv: "Ed25519", x: jwk.x } };
}

const b64u = (value: unknown) => bytesToBase64Url(stringToUtf8(JSON.stringify(value)));

/**
 * Builds a DPoP proof JWT for one request. `htu` is the URL without query or fragment. Pass the access token
 * to add `ath` (its SHA-256, base64url) when presenting it with `Authorization: DPoP`.
 */
export async function createDpopProof(
  key: DpopKey,
  params: { method: string; url: string; accessToken?: string }
): Promise<string> {
  const u = new URL(params.url);
  const header = { typ: "dpop+jwt", alg: "EdDSA", jwk: key.publicJwk };
  const claims: Record<string, unknown> = {
    jti: webcrypto.randomUUID(),
    htm: params.method.toUpperCase(),
    htu: `${u.origin}${u.pathname}`,
    iat: Math.floor(Date.now() / 1000),
  };
  if (params.accessToken) claims.ath = await sha256Base64Url(params.accessToken);
  const signingInput = `${b64u(header)}.${b64u(claims)}`;
  const sig = new Uint8Array(await webcrypto.sign({ name: "Ed25519" } as any, key.privateKey, stringToUtf8(signingInput) as BufferSource));
  return `${signingInput}.${bytesToBase64Url(sig)}`;
}

/** Longest accepted DPoP proof (bytes). A proof is a small JWT; anything bigger is refused unparsed. */
export const MAX_DPOP_PROOF_LENGTH = 4096;
/** How old (or how far in the future) a proof's `iat` may be. */
export const DPOP_MAX_AGE_SECONDS = 60;

/** Proof `jti`s seen recently, per process. Pass a shared `ReplayStore` when several instances verify. */
export const globalDpopReplayCache = new SignatureReplayCache();

export interface VerifyDpopProofParams {
  /** The `DPoP` request header. */
  proof: string;
  /** The request method. */
  method: string;
  /** The URL the client called (its scheme, host and path must match the proof's `htu`). */
  url: string;
  /** The access token presented with `Authorization: DPoP`; the proof's `ath` must be its SHA-256. */
  accessToken: string;
  /** The token's `cnf.jkt`: the RFC 7638 thumbprint of the key the token is bound to. */
  expectedJkt: string;
  currentTime?: number;
  /** At most `DPOP_MAX_AGE_SECONDS`. */
  maxAgeSeconds?: number;
  replayStore?: ReplayStore;
}

/** Normalized `htu`: scheme, host and path, no query or fragment (RFC 9449 §4.3). */
function htuOf(value: string): string | null {
  try {
    const u = new URL(value);
    if (u.protocol !== "https:" && u.protocol !== "http:") return null;
    return `${u.protocol}//${u.host}${u.pathname}`;
  } catch {
    return null;
  }
}

const B64URL = /^[A-Za-z0-9_-]+$/;

/** RFC 7638 thumbprint of an Ed25519 or P-256 public JWK, or null for any other (or a private) key. */
async function proofKey(jwk: unknown): Promise<{ key: CryptoKey; jkt: string; alg: "EdDSA" | "ES256" } | null> {
  if (!jwk || typeof jwk !== "object" || Array.isArray(jwk)) return null;
  const k = jwk as Record<string, unknown>;
  if ("d" in k || "p" in k || "q" in k) return null; // never a private key
  if (k.kty === "OKP" && k.crv === "Ed25519" && typeof k.x === "string" && B64URL.test(k.x)) {
    const key = await webcrypto.importKey("jwk", { kty: "OKP", crv: "Ed25519", x: k.x }, { name: "Ed25519" } as any, false, ["verify"]);
    return { key, jkt: await sha256Base64Url(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: k.x })), alg: "EdDSA" };
  }
  if (k.kty === "EC" && k.crv === "P-256" && typeof k.x === "string" && typeof k.y === "string" && B64URL.test(k.x) && B64URL.test(k.y)) {
    const key = await webcrypto.importKey("jwk", { kty: "EC", crv: "P-256", x: k.x, y: k.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
    return { key, jkt: await sha256Base64Url(JSON.stringify({ crv: "P-256", kty: "EC", x: k.x, y: k.y })), alg: "ES256" };
  }
  return null;
}

/**
 * Verifies the DPoP proof that must accompany a DPoP-bound (`cnf.jkt`) access token (RFC 9449 §4.3 and
 * §7.1): `typ: dpop+jwt`, EdDSA or ES256 signed by the public key in its `jwk` header (whose thumbprint must
 * equal the token's `cnf.jkt`), `htm` / `htu` matching this request, a recent `iat`, an `ath` equal to the
 * SHA-256 of the access token, and a `jti` never seen before. Without a valid proof a bound token is useless
 * to whoever copied it.
 */
export async function verifyDpopProof(params: VerifyDpopProofParams): Promise<{ valid: boolean; error?: string }> {
  try {
    const { proof } = params;
    if (typeof proof !== "string" || proof.length === 0 || proof.length > MAX_DPOP_PROOF_LENGTH) {
      return { valid: false, error: "Missing or oversized DPoP proof" };
    }
    const parts = proof.split(".");
    if (parts.length !== 3) return { valid: false, error: "DPoP proof is not a JWT" };
    let header: Record<string, unknown>;
    let claims: Record<string, unknown>;
    let signature: Uint8Array;
    try {
      header = JSON.parse(utf8ToString(base64UrlToBytesStrict(parts[0])));
      claims = JSON.parse(utf8ToString(base64UrlToBytesStrict(parts[1])));
      signature = base64UrlToBytesStrict(parts[2]);
    } catch {
      return { valid: false, error: "DPoP proof segments must be canonical base64url JSON" };
    }
    if (!header || typeof header !== "object" || Array.isArray(header) || !claims || typeof claims !== "object" || Array.isArray(claims)) {
      return { valid: false, error: "DPoP proof header and claims must be JSON objects" };
    }
    if (header.typ !== "dpop+jwt") return { valid: false, error: "DPoP proof typ must be dpop+jwt" };
    if (header.crit !== undefined) return { valid: false, error: "Unsupported DPoP crit header" };
    const key = await proofKey(header.jwk);
    if (!key) return { valid: false, error: "DPoP proof jwk must be an Ed25519 or P-256 public key" };
    if (header.alg !== key.alg) return { valid: false, error: `DPoP proof alg must be ${key.alg} for this key` };

    const signed = stringToUtf8(`${parts[0]}.${parts[1]}`) as BufferSource;
    const ok =
      key.alg === "EdDSA"
        ? await webcrypto.verify({ name: "Ed25519" } as any, key.key, signature as BufferSource, signed)
        : await webcrypto.verify({ name: "ECDSA", hash: "SHA-256" }, key.key, signature as BufferSource, signed);
    if (!ok) return { valid: false, error: "DPoP proof signature verification failed" };

    if (typeof params.expectedJkt !== "string" || !timingSafeEqualString(key.jkt, params.expectedJkt)) {
      return { valid: false, error: "DPoP proof key does not match the token's cnf.jkt" };
    }
    if (typeof claims.htm !== "string" || claims.htm !== params.method.toUpperCase()) {
      return { valid: false, error: "DPoP proof htm does not match the request method" };
    }
    const expectedHtu = htuOf(params.url);
    if (!expectedHtu || typeof claims.htu !== "string" || htuOf(claims.htu) !== expectedHtu) {
      return { valid: false, error: "DPoP proof htu does not match the request URL" };
    }
    const now = Number.isFinite(params.currentTime) ? (params.currentTime as number) : Math.floor(Date.now() / 1000);
    const maxAgeOption = Number.isFinite(params.maxAgeSeconds) ? (params.maxAgeSeconds as number) : DPOP_MAX_AGE_SECONDS;
    const maxAge = Math.max(1, Math.min(maxAgeOption, DPOP_MAX_AGE_SECONDS));
    if (typeof claims.iat !== "number" || !Number.isFinite(claims.iat) || Math.abs(now - claims.iat) > maxAge) {
      return { valid: false, error: "DPoP proof iat is missing or outside the accepted window" };
    }
    const ath = await sha256Base64Url(params.accessToken);
    if (typeof claims.ath !== "string" || !timingSafeEqualString(claims.ath, ath)) {
      return { valid: false, error: "DPoP proof ath does not match the access token" };
    }
    if (typeof claims.jti !== "string" || claims.jti.length === 0 || claims.jti.length > 256) {
      return { valid: false, error: "DPoP proof has no usable jti" };
    }
    const store = params.replayStore ?? globalDpopReplayCache;
    if (!(await store.record(`dpop:${key.jkt}:${claims.jti}`, 2 * maxAge * 1000))) {
      return { valid: false, error: "DPoP proof replayed (jti already used)" };
    }
    return { valid: true };
  } catch (err) {
    return { valid: false, error: `DPoP proof verification error: ${(err as Error).message}` };
  }
}
