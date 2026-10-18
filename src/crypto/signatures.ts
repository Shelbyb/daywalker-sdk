import { webcrypto } from "./webcrypto.js";
import type { PublicJwk, PublicJwks, ReplayStore, SigningKey, SignedHeaders, SignRequestParams, VerifySignatureParams, VerifySignatureResult } from "../types.js";
import {
  base64ToBytes,
  base64UrlToBytesStrict,
  bytesToBase64,
  bytesToHex,
  stringToUtf8,
  utf8ToString,
  timingSafeEqualString,
  redactSecrets,
} from "./encoding.js";
import { computeContentDigest } from "./digest.js";
import { loadPublicKey, loadSigningKey } from "./keys.js";
import { assertSecureUrl, parseServiceSlugs, publicHostname } from "../config.js";

export const SIGNATURE_VERSION = "rfc9421";
export const SIGNATURE_LABEL = "sig1";
export const SIGNATURE_ALG = "ed25519";
export const MAX_CLOCK_SKEW_SECONDS = 300;
export const SAFE_IDENTIFIER_PATTERN = /^[a-zA-Z0-9_\-\.]{1,128}$/;
/** A Daywalker service slug. */
export const SERVICE_SLUG_PATTERN = /^[a-z0-9][a-z0-9_-]{0,63}$/;
/** An API key: printable, no whitespace, quotes or separators that could break out of a header. */
export const API_KEY_PATTERN = /^[A-Za-z0-9_.~+\/=-]{8,512}$/;

/**
 * Splits a request target into its RFC 9421 "@path" value (§2.2.6; dot segments resolved and repeated
 * slashes collapsed per RFC 3986, to prevent path traversal & signature confusion) and its "@query" value
 * (§2.2.7; the query with its leading "?", or "?" alone when there is none). Fragments are dropped.
 */
export function splitRequestTarget(rawTarget: string): { path: string; query: string } {
  if (!rawTarget || !rawTarget.trim()) return { path: "/", query: "?" };
  const t = rawTarget.trim().replace(/^[^?#]*/, (p) => p.replace(/\/+/g, "/"));
  try {
    const parsed = new URL(t, "http://localhost");
    return { path: parsed.pathname, query: parsed.search || "?" };
  } catch {
    const p = t.replace(/[?#].*$/, "");
    return { path: p.startsWith("/") ? p : `/${p}`, query: "?" };
  }
}

/**
 * Normalizes an HTTP request path per RFC 3986 into the "@path" component. Path only: the query string is
 * a separate "@query" component (see `splitRequestTarget`).
 */
export function normalizePath(rawPath: string): string {
  return splitRequestTarget(rawPath).path;
}

/** Methods whose requests always cover "content-digest" (of the empty body when there is none). */
const BODY_METHODS = new Set(["POST", "PUT", "PATCH"]);
/** Derived components this implementation can compute; header field names must be lowercase. */
const DERIVED_COMPONENTS = new Set(["@method", "@path", "@query", "@authority"]);
const COMPONENT_NAME_PATTERN = /^@?[a-z0-9][a-z0-9_.-]*$/;

/**
 * Validates that an identifier (keyId, serviceSlug, etc.) contains only safe alphanumeric/hyphen characters.
 */
export function assertSafeIdentifier(name: string, value: string): void {
  if (!value || typeof value !== "string" || value.length > 128 || !SAFE_IDENTIFIER_PATTERN.test(value)) {
    throw new Error(`Invalid ${name}: must be 1-128 safe characters (alphanumeric, '_', '-', '.')`);
  }
}

/**
 * Upper bound on remembered signatures. Unexpired entries are never evicted: once the cache is full of them,
 * new signatures are rejected (fail closed) until entries expire. Entries live 2 x maxClockSkewSeconds
 * (600s by default), so the default sustains ~160 verified requests/s per process.
 */
export const REPLAY_CACHE_MAX_ENTRIES = 100_000;

/**
 * In-memory replay cache, keyed on keyid + decoded signature bytes (so re-encodings of the
 * same signature collide). Per process only: multi-instance deployments need a shared `ReplayStore`.
 */
export class SignatureReplayCache implements ReplayStore {
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

  /**
   * Records `key` until `now + ttlMs`. Returns false, recording nothing, when the key is already present
   * or the cache is full of unexpired entries (a still-valid signature is never forgotten early).
   */
  public record(key: string, ttlMs: number, now = Date.now()): boolean {
    if (this.has(key, now)) return false;
    this.seen.delete(key);
    if (this.seen.size >= this.maxEntries) {
      for (const [k, exp] of this.seen) {
        if (exp <= now) this.seen.delete(k);
      }
      if (this.seen.size >= this.maxEntries) return false;
    }
    this.seen.set(key, now + ttlMs);
    return true;
  }

  public clear(): void {
    this.seen.clear();
  }
}

export const globalReplayCache = new SignatureReplayCache();

export type {
  ReplayStore,
  SignedHeaders,
  SignRequestParams,
  VerifySignatureParams,
  VerifySignatureResult,
};

/**
 * Format the RFC 9421 Signature-Input parameters string.
 * Example: `("@method" "@path" "@authority" "content-digest");created=1791561600;keyid="...";alg="ed25519";nonce="..."`
 * Every value is validated, so none can close its quoted string and inject parameters.
 */
export function formatSignatureParams(params: {
  components?: string[];
  created: number;
  keyid: string;
  alg?: string;
  nonce?: string;
}): string {
  const components = params.components ?? ["@method", "@path", "@authority", "content-digest"];
  for (const c of components) {
    if (!COMPONENT_NAME_PATTERN.test(c) || c === "@signature-params") {
      throw new Error(`Invalid covered component: ${JSON.stringify(c)}`);
    }
  }
  if (!Number.isSafeInteger(params.created) || params.created < 0) {
    throw new Error("Invalid created: must be a non-negative integer of unix seconds");
  }
  const alg = params.alg ?? SIGNATURE_ALG;
  assertSafeIdentifier("keyid", params.keyid);
  assertSafeIdentifier("alg", alg);
  const componentsStr = components.map((c) => `"${c}"`).join(" ");
  let out = `(${componentsStr});created=${params.created};keyid="${params.keyid}";alg="${alg}"`;
  if (params.nonce) {
    assertSafeIdentifier("nonce", params.nonce);
    out += `;nonce="${params.nonce}"`;
  }
  return out;
}

/**
 * Parses a Signature-Input member value (RFC 8941 inner list of plain quoted component names, then
 * `;key=value` parameters with integer or string values). Returns an error string when malformed.
 */
function parseSignatureParams(input: string): { components: string[]; params: Record<string, string | number> } | string {
  const listMatch = input.match(/^\(([^()]*)\)(.*)$/);
  if (!listMatch) return "Signature-Input missing covered components list";
  const inner = listMatch[1].trim();
  const components: string[] = [];
  for (const item of inner ? inner.split(/ +/) : []) {
    const m = item.match(/^"([^"\\]*)"$/);
    if (!m || !COMPONENT_NAME_PATTERN.test(m[1])) {
      return `Unsupported covered component in Signature-Input: ${item}`;
    }
    components.push(m[1]);
  }
  const params: Record<string, string | number> = {};
  const paramPattern = /;([a-z*][a-z0-9_.*-]*)=(\d{1,15}|"[^"\\]*")/y;
  let rest = listMatch[2];
  while (rest.length > 0) {
    paramPattern.lastIndex = 0;
    const m = paramPattern.exec(rest);
    if (!m) return "Malformed Signature-Input parameters";
    if (Object.prototype.hasOwnProperty.call(params, m[1])) return `Duplicate Signature-Input parameter: ${m[1]}`;
    params[m[1]] = m[2].startsWith('"') ? m[2].slice(1, -1) : parseInt(m[2], 10);
    rest = rest.slice(m[0].length);
  }
  return { components, params };
}

/**
 * Construct canonical RFC 9421 signature base string from the covered components, in order. They are
 * `components` when given, else the list declared in `signatureParams`. "@path" and "@query" come from
 * `path` (which may carry a query string); "content-digest" from `contentDigest`; any other header field
 * from `additionalComponents`. Throws when a covered component has no value.
 */
export function createSignatureBase(params: {
  method: string;
  path: string;
  authority: string;
  contentDigest?: string | null;
  signatureParams: string;
  additionalComponents?: Record<string, string>;
  components?: string[];
}): string {
  const target = splitRequestTarget(params.path);
  let components = params.components;
  if (!components) {
    const parsed = parseSignatureParams(params.signatureParams);
    components =
      typeof parsed !== "string"
        ? parsed.components
        : [
            "@method",
            "@path",
            "@authority",
            ...(params.contentDigest !== undefined && params.contentDigest !== null ? ["content-digest"] : []),
            ...Object.keys(params.additionalComponents ?? {}),
          ];
  }
  const additional: Record<string, string> = {};
  for (const [k, v] of Object.entries(params.additionalComponents ?? {})) additional[k.toLowerCase()] = v;

  const lines: string[] = [];
  for (const raw of components) {
    const name = raw.toLowerCase();
    let value: string | null | undefined;
    if (name === "@method") value = params.method.toUpperCase();
    else if (name === "@path") value = target.path;
    else if (name === "@query") value = target.query;
    else if (name === "@authority") value = params.authority.toLowerCase();
    else if (name.startsWith("@")) throw new Error(`Unsupported derived component: ${name}`);
    else if (name === "content-digest") value = params.contentDigest ?? additional[name];
    else value = additional[name];
    if (value === undefined || value === null) {
      throw new Error(`Covered component ${name} has no value`);
    }
    value = value.trim();
    if (/[\r\n]/.test(value)) {
      throw new Error(`Covered component ${name} contains a line break`);
    }
    lines.push(`"${name}": ${value}`);
  }

  lines.push(`"@signature-params": ${params.signatureParams}`);
  return lines.join("\n");
}

/**
 * Sign an outgoing HTTP request according to RFC 9421 + RFC 9530.
 * Covers "@method", "@path", "@query" (only when `path` has a query string), "@authority" and
 * "content-digest" (whenever there is a body, and always for POST / PUT / PATCH).
 */
export async function signRequest(params: SignRequestParams): Promise<SignedHeaders> {
  const signer = params.signer;
  if (!signer && !params.key) throw new Error("signRequest needs a key or a signer");
  const signingKey = signer ? null : await loadSigningKey(params.key!);
  const created = params.created ?? Math.floor(Date.now() / 1000);
  const keyid = params.keyid ?? (signer ? signer.keyId : signingKey!.publicJwk.kid);
  const alg = params.alg ?? SIGNATURE_ALG;
  const method = params.method.toUpperCase();

  const body = params.body ?? (BODY_METHODS.has(method) ? "" : null);
  const contentDigest = body !== null ? await computeContentDigest(body) : null;

  const components = ["@method", "@path"];
  if (splitRequestTarget(params.path).query !== "?") {
    components.push("@query");
  }
  components.push("@authority");
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
    method,
    path: params.path,
    authority: params.authority,
    contentDigest,
    signatureParams,
    components,
  });

  const baseBytes = stringToUtf8(signatureBase);
  const signatureBuffer = signer
    ? await signer.sign(baseBytes)
    : await webcrypto.sign("Ed25519", signingKey!.privateKey, baseBytes as unknown as BufferSource);
  if (!(signatureBuffer instanceof ArrayBuffer || signatureBuffer instanceof Uint8Array) || signatureBuffer.byteLength !== 64) {
    throw new Error("Signer must return a 64-byte Ed25519 signature");
  }

  const signatureBase64 = bytesToBase64(new Uint8Array(signatureBuffer));

  const headers: SignedHeaders = {
    "Signature-Input": `${SIGNATURE_LABEL}=${signatureParams}`,
    Signature: `${SIGNATURE_LABEL}=:${signatureBase64}:`,
  };

  if (contentDigest !== null) {
    headers["Content-Digest"] = contentDigest;
  }

  return headers;
}

/**
 * Verify an incoming RFC 9421 HTTP Message Signature. The signature base is built from the components the
 * signature declares, which must include "@method", "@path" and "@authority", plus "@query" when the request
 * has a query string and "content-digest" when it has a body or is a POST / PUT / PATCH.
 * Replay protection uses `replayStore` (default: per-process memory; use a shared store across instances).
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
  const parsed = parseSignatureParams(signatureParams);
  if (typeof parsed === "string") {
    return { valid: false, error: parsed };
  }
  const components = parsed.components;
  const seenComponents = new Set<string>();
  for (const c of components) {
    if (seenComponents.has(c)) {
      return { valid: false, error: `Duplicate covered component in Signature-Input: ${c}` };
    }
    seenComponents.add(c);
  }
  for (const required of ["@method", "@path", "@authority"]) {
    if (!seenComponents.has(required)) {
      return { valid: false, error: `Signature does not cover ${required}` };
    }
  }
  if (splitRequestTarget(params.path).query !== "?" && !seenComponents.has("@query")) {
    return { valid: false, error: "Request has a query string but the signature does not cover @query" };
  }
  const body = params.body;
  const hasBody = body !== undefined && body !== null && (typeof body === "string" ? body.length > 0 : body.byteLength > 0);
  if ((hasBody || BODY_METHODS.has(params.method.toUpperCase())) && !seenComponents.has("content-digest")) {
    return { valid: false, error: "Request has a body but the signature does not cover content-digest" };
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

  const created = parsed.params.created;
  if (typeof created !== "number") {
    return { valid: false, error: "Signature-Input missing created timestamp" };
  }
  const now = params.currentTime ?? Math.floor(Date.now() / 1000);
  const maxSkew = params.maxClockSkewSeconds ?? MAX_CLOCK_SKEW_SECONDS;

  if (Math.abs(now - created) > maxSkew) {
    return { valid: false, error: `Signature timestamp expired or clock skew too large (created=${created}, now=${now})` };
  }

  const keyidParam = parsed.params.keyid;
  if (keyidParam !== undefined && typeof keyidParam !== "string") {
    return { valid: false, error: "Signature-Input keyid must be a string" };
  }
  const keyid = keyidParam || undefined;
  if (keyid) {
    try {
      assertSafeIdentifier("keyid", keyid);
    } catch (e) {
      return { valid: false, error: (e as Error).message };
    }
  }

  // Entries must outlive the whole acceptance window (created ± maxSkew).
  const replayStore = params.replayStore ?? globalReplayCache;
  const replayKey = `${keyid ?? ""}:${bytesToHex(signatureBytes)}`;
  const replayTtlMs = 2 * Math.max(maxSkew, 1) * 1000;
  if (params.replayCheck !== false && (await replayStore.has(replayKey))) {
    return { valid: false, error: "Replay detected: request signature was already presented" };
  }

  const alg = parsed.params.alg;
  if (alg !== undefined && (typeof alg !== "string" || (alg.toLowerCase() !== "ed25519" && alg.toLowerCase() !== "eddsa"))) {
    return { valid: false, error: `Unsupported signature algorithm: ${alg}` };
  }

  if (seenComponents.has("content-digest")) {
    if (!contentDigestHeader) {
      return { valid: false, error: "Signature covers content-digest but Content-Digest header is missing" };
    }
    const computedDigest = await computeContentDigest(params.body ?? "");
    if (!computedDigest || !timingSafeEqualString(contentDigestHeader.trim(), computedDigest)) {
      return { valid: false, error: `Content-Digest mismatch: expected ${computedDigest}, got ${contentDigestHeader}` };
    }
  }

  try {
    const additionalComponents: Record<string, string> = {};
    for (const c of components) {
      if (c.startsWith("@") || c === "content-digest") continue;
      const value = getHeader(c);
      if (value === undefined) {
        return { valid: false, error: `Signature covers ${c} but the request has no such header` };
      }
      additionalComponents[c] = value;
    }

    const signatureBase = createSignatureBase({
      method: params.method,
      path: params.path,
      authority: params.authority,
      contentDigest: contentDigestHeader?.trim() ?? null,
      signatureParams,
      additionalComponents,
      components,
    });

    const { publicKey } = await loadPublicKey(params.publicKey, keyid);

    const isValid = await webcrypto.verify(
      "Ed25519",
      publicKey,
      signatureBytes as unknown as BufferSource,
      stringToUtf8(signatureBase) as unknown as BufferSource
    );

    if (!isValid) {
      return { valid: false, error: "Cryptographic signature verification failed" };
    }

    // Record only verified signatures. `record` is set-if-absent, so a concurrent copy that won the race,
    // or a store too full to remember this signature, makes it fail closed.
    if (params.replayCheck !== false && !(await replayStore.record(replayKey, replayTtlMs))) {
      const full = !(await replayStore.has(replayKey));
      return {
        valid: false,
        error: full
          ? "Replay cache is full: refusing a signature that could not be remembered"
          : "Replay detected: request signature was already presented",
      };
    }

    return { valid: true, keyid };
  } catch (err) {
    return { valid: false, error: `Verification error: ${(err as Error).message}` };
  }
}

/** Every service slug a (verified) access token covers: its `services` claim, else its audience. */
export function leaseServices(payload: Record<string, unknown>): string[] {
  const strings = (v: unknown): string[] =>
    (Array.isArray(v) ? v : v === undefined || v === null ? [] : [v]).filter((s): s is string => typeof s === "string" && s !== "");
  const listed = strings(payload.services);
  const fallback = listed.length > 0 ? listed : strings(payload.aud);
  return Array.from(new Set(fallback.map((s) => s.toLowerCase())));
}

/** Clock skew tolerated on JWT `exp` / `nbf`: 30 seconds, and never more (see `clockSkewSeconds`). */
export const JWT_CLOCK_SKEW_SECONDS = 30;
/** Longest accepted JWT (characters); longer input is refused before any parsing. */
export const MAX_JWT_LENGTH = 16_384;

/**
 * Zero-egress offline verification of Daywalker access tokens (RFC 9068 JWTs from the OAuth token endpoint).
 * Requires `typ: at+jwt`, `alg: EdDSA`, a `jti`, a numeric `exp`, and an `aud` containing `expectedServiceSlug`
 * (a verifier without an expected slug rejects every token). `iss` is checked when `expectedIssuer` is set.
 * Segments must be canonical unpadded base64url, a `crit` header is rejected, and a JWKS `publicKey` is
 * searched by the header's `kid`. A token with `cnf.jkt` is DPoP-bound: the caller must also check its
 * proof (`verifyDpopProof`), as `Daywalker.validateToken()` does.
 */
export async function verifyJwtLease(params: {
  token: string;
  publicKey: string | PublicJwk | PublicJwks | CryptoKey;
  expectedServiceSlug?: string;
  expectedIssuer?: string;
  currentTime?: number;
  clockSkewSeconds?: number;
}): Promise<{ valid: boolean; payload?: Record<string, unknown>; error?: string }> {
  try {
    if (typeof params.token !== "string" || params.token.length > MAX_JWT_LENGTH) {
      return { valid: false, error: "Token is not a string or is too long" };
    }
    const parts = params.token.trim().split(".");
    if (parts.length !== 3) {
      return { valid: false, error: "Token is not a valid 3-part JWT" };
    }

    const [headerB64, payloadB64, signatureB64] = parts;
    let headerJson: string;
    let payloadJson: string;
    let signatureBytes: Uint8Array;
    try {
      headerJson = utf8ToString(base64UrlToBytesStrict(headerB64));
      payloadJson = utf8ToString(base64UrlToBytesStrict(payloadB64));
      signatureBytes = base64UrlToBytesStrict(signatureB64);
    } catch {
      return { valid: false, error: "JWT segments must be canonical unpadded base64url" };
    }

    const header = JSON.parse(headerJson);
    const payload = JSON.parse(payloadJson);
    if (!header || typeof header !== "object" || !payload || typeof payload !== "object" || Array.isArray(payload)) {
      return { valid: false, error: "JWT header and payload must be JSON objects" };
    }

    if (header.alg !== "EdDSA") {
      return { valid: false, error: `Unsupported JWT alg: ${header.alg}` };
    }
    // RFC 9068 §4: only access tokens; a refresh token, ID token or any other JWT under the same key is refused
    if (typeof header.typ !== "string" || header.typ.toLowerCase() !== "at+jwt") {
      return { valid: false, error: `Unsupported JWT typ: ${header.typ}` };
    }
    // RFC 7515 §4.1.11: extensions we don't understand must be rejected; we implement none.
    if (header.crit !== undefined) {
      return { valid: false, error: "Unsupported JWT crit header" };
    }
    if (header.kid !== undefined && typeof header.kid !== "string") {
      return { valid: false, error: "JWT kid must be a string" };
    }

    const { publicKey } = await loadPublicKey(params.publicKey, header.kid);
    const signedData = stringToUtf8(`${headerB64}.${payloadB64}`);

    const isValid = await webcrypto.verify(
      "Ed25519",
      publicKey,
      signatureBytes as unknown as BufferSource,
      signedData as unknown as BufferSource
    );

    if (!isValid) {
      return { valid: false, error: "JWT signature verification failed" };
    }

    const now = params.currentTime ?? Math.floor(Date.now() / 1000);
    const skew = Math.max(0, Math.min(params.clockSkewSeconds ?? JWT_CLOCK_SKEW_SECONDS, JWT_CLOCK_SKEW_SECONDS));
    if (typeof payload.jti !== "string" || payload.jti === "") {
      return { valid: false, error: "JWT has no jti claim" };
    }
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
    const audiences: string[] = (Array.isArray(payload.aud) ? payload.aud : payload.aud === undefined ? [] : [payload.aud]).filter(
      (a: unknown): a is string => typeof a === "string"
    );
    if (audiences.length === 0) {
      return { valid: false, error: "JWT has no aud claim" };
    }
    if (!audiences.some((a: string) => a.toLowerCase() === expected)) {
      return {
        valid: false,
        error: `JWT audience mismatch: expected ${expected}, got ${audiences.join(", ").toLowerCase()}`,
      };
    }
    if (payload.cnf !== undefined && (!payload.cnf || typeof payload.cnf !== "object" || typeof payload.cnf.jkt !== "string")) {
      return { valid: false, error: "JWT cnf claim must carry a jkt thumbprint" };
    }

    // A lease that lists its services must list this one (belt and braces next to `aud`).
    if (payload.services !== undefined) {
      const listed = Array.isArray(payload.services) ? payload.services : null;
      if (!listed || !listed.some((s: unknown) => typeof s === "string" && s.toLowerCase() === expected)) {
        return {
          valid: false,
          error: `JWT services mismatch: expected ${expected}, got ${listed ? listed.map(String).join(", ").toLowerCase() : "(not a list)"}`,
        };
      }
    }

    if (params.expectedIssuer && payload.iss !== params.expectedIssuer) {
      return { valid: false, error: `JWT issuer mismatch: expected ${params.expectedIssuer}, got ${payload.iss ?? "(none)"}` };
    }

    return { valid: true, payload };
  } catch (err) {
    return { valid: false, error: `Failed to verify JWT lease: ${(err as Error).message}` };
  }
}

/** Per-attempt timeout for key registration. */
const REGISTER_TIMEOUT_MS = 10_000;

/**
 * Register public key directly with Daywalker Auth via POST /api/v1/keys/register (Push Architecture).
 * The API key is sent as `Authorization: Bearer` to `authUrl` only: redirects are refused (never followed
 * with the key), the request times out after 10s, and nothing is cached. Inputs are validated first.
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
  const domain = publicHostname(params.domain);
  if (!domain) {
    return { ok: false, status: 400, error: `domain (${params.domain}) is not a public hostname` };
  }
  if (typeof params.apiKey !== "string" || !API_KEY_PATTERN.test(params.apiKey)) {
    return { ok: false, status: 400, error: "apiKey is missing or contains characters an API key can't have" };
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

  try {
    const res = await doFetch(registerUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        Authorization: `Bearer ${params.apiKey}`,
      },
      body: JSON.stringify({
        keyId: jwk.kid,
        domain,
        publicKey: { kty: "OKP", crv: "Ed25519", x: jwk.x, kid: jwk.kid, use: "sig", alg: "EdDSA" },
        // Lets Daywalker refuse right away when the API key doesn't cover the service(s); a comma-separated list is fine
        ...(slugs.length > 0 ? { serviceSlug: slugs.join(",") } : {}),
      }),
      redirect: "manual",
      cache: "no-store",
      signal: AbortSignal.timeout(REGISTER_TIMEOUT_MS),
    });

    if (res.type === "opaqueredirect" || (res.status >= 300 && res.status < 400)) {
      return { ok: false, status: res.status, error: "Daywalker Auth answered with a redirect; refusing to follow it with the API key" };
    }
    if (res.ok) {
      return { ok: true, status: res.status };
    }

    const data = (await res.json().catch(() => ({}))) as { message?: unknown; error?: unknown };
    const message = typeof data.message === "string" ? data.message : typeof data.error === "string" ? data.error : `HTTP ${res.status}`;
    return { ok: false, status: res.status, error: redactSecrets(message.slice(0, 500)) };
  } catch (err) {
    return { ok: false, status: 0, error: redactSecrets((err as Error).message) };
  }
}
