/**
 * Zero-dependency Web standard encoding utilities.
 * Runs in Node.js 18+, Bun, Deno, Cloudflare Workers, and browser/Edge runtimes.
 */

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function stringToUtf8(str: string): Uint8Array {
  return encoder.encode(str);
}

export function utf8ToString(bytes: Uint8Array): string {
  return decoder.decode(bytes);
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== "undefined") {
    return Buffer.from(bytes).toString("base64");
  }
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  const clean = b64.trim().replace(/\s+/g, "");
  if (typeof Buffer !== "undefined") {
    const buf = Buffer.from(clean, "base64");
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
  }
  const binary = atob(clean);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToBase64Url(bytes: Uint8Array): string {
  return bytesToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlToBytes(b64url: string): Uint8Array {
  let b64 = b64url.trim().replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4 !== 0) {
    b64 += "=";
  }
  return base64ToBytes(b64);
}

/**
 * Decodes unpadded base64url (RFC 7515 §2) strictly: only `[A-Za-z0-9_-]` and only the canonical encoding
 * of the bytes, so a token or signature has exactly one accepted spelling. Throws otherwise.
 */
export function base64UrlToBytesStrict(b64url: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(b64url) || b64url.length % 4 === 1) {
    throw new Error("Invalid base64url encoding");
  }
  const bytes = base64UrlToBytes(b64url);
  if (bytesToBase64Url(bytes) !== b64url) {
    throw new Error("Non-canonical base64url encoding");
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.trim().replace(/^0x/i, "");
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) throw new Error("Invalid hex string");
  const bytes = new Uint8Array(clean.length / 2);
  for (let i = 0; i < clean.length; i += 2) {
    bytes[i / 2] = parseInt(clean.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Constant-time byte comparison to mitigate microarchitectural timing attacks.
 */
export function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.byteLength !== b.byteLength) return false;
  let diff = 0;
  for (let i = 0; i < a.byteLength; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

/**
 * Constant-time string comparison helper.
 */
export function timingSafeEqualString(a: string, b: string): boolean {
  return timingSafeEqual(stringToUtf8(a), stringToUtf8(b));
}

/**
 * Masks a secret string for safe display/logging (e.g. `srv_...cdef` or `[none]`).
 */
export function maskSecret(val: string | null | undefined): string {
  if (!val || typeof val !== "string") return "[none]";
  if (val.length <= 8) return "***";
  return `${val.slice(0, 4)}...${val.slice(-4)}`;
}

/**
 * Redacts secrets, tokens, keys, and authorization headers from strings.
 * Used across SDK error handlers and logs to prevent sensitive credential exposure.
 */
export function redactSecrets(input: string | null | undefined): string {
  if (!input || typeof input !== "string") return "";
  let out = input;

  // Bearer tokens & Authorization headers
  out = out.replace(/(Bearer\s+)[A-Za-z0-9_\-\.]+/gi, "$1[REDACTED]");

  // API keys (e.g. srv_live_..., srv_test_..., dw_...)
  out = out.replace(/\b(srv_(?:live|test)_[a-zA-Z0-9_\-]+)\b/g, (match) => {
    if (match.length <= 12) return "[REDACTED_KEY]";
    return `${match.slice(0, 8)}...[REDACTED]`;
  });
  out = out.replace(/\b(dw_[a-zA-Z0-9_\-]+)\b/g, "[REDACTED_KEY]");

  // Standard JWTs (header.payload.signature)
  out = out.replace(/\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b/g, "[REDACTED_JWT]");

  // PEM Private keys
  out = out.replace(/-----BEGIN [A-Z\s]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+ PRIVATE KEY-----/g, "[REDACTED_PRIVATE_KEY]");

  // Query parameters in URLs like ?apiKey=... &token=...
  out = out.replace(/([?&](?:apiKey|api_key|token|signingKey|signing_key|secret)=)[^&\s]+/gi, "$1[REDACTED]");

  return out;
}
