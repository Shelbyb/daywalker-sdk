import { bytesToBase64, stringToUtf8 } from "./encoding.js";

/** Default upper bound for body payload digest calculation (10MB). */
export const DEFAULT_MAX_BODY_SIZE_BYTES = 10 * 1024 * 1024;

/**
 * RFC 9530 Digest Fields computation.
 * Hashes payload with SHA-256 via WebCrypto `crypto.subtle.digest`.
 * Formats as `sha-256=:<base64-digest>:` (RFC 9651 structured field byte sequence).
 * Enforces body size limit to mitigate memory exhaustion DoS.
 */
export async function computeContentDigest(
  body: Uint8Array | string | null | undefined,
  maxSizeBytes: number = DEFAULT_MAX_BODY_SIZE_BYTES
): Promise<string | null> {
  if (body === null || body === undefined) {
    return null;
  }
  const data = typeof body === "string" ? stringToUtf8(body) : body;
  if (data.byteLength > maxSizeBytes) {
    throw new Error(`Request body size (${data.byteLength} bytes) exceeds maximum allowed limit (${maxSizeBytes} bytes)`);
  }
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", data as unknown as BufferSource);
  const hashBase64 = bytesToBase64(new Uint8Array(hashBuffer));
  return `sha-256=:${hashBase64}:`;
}

/**
 * Compute SHA-256 hash returned as base64 string.
 */
export async function sha256Base64(data: Uint8Array | string): Promise<string> {
  const bytes = typeof data === "string" ? stringToUtf8(data) : data;
  const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", bytes as unknown as BufferSource);
  return bytesToBase64(new Uint8Array(hashBuffer));
}

/**
 * Compute SHA-256 hash returned as base64url string (useful for JWK thumbprints).
 */
export async function sha256Base64Url(data: Uint8Array | string): Promise<string> {
  const base64 = await sha256Base64(data);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
