import type { KeyStore, StoredSigningKey } from "../types.js";
import { SAFE_IDENTIFIER_PATTERN } from "../crypto/signatures.js";
import { publicHostname } from "../config.js";

export type { KeyStore, StoredSigningKey } from "../types.js";

/** Longest accepted base64 PKCS#8 private key (an Ed25519 one is 64 characters). */
const MAX_PKCS8_BASE64_LENGTH = 512;

/**
 * Checks that `value` is a well-formed `StoredSigningKey` and returns a clean copy (unknown fields dropped),
 * or throws. Run on everything a store returns, so a corrupted or hand-edited record is refused rather than used.
 */
export function parseStoredSigningKey(value: unknown): StoredSigningKey {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Stored signing key is not an object");
  const v = value as Record<string, unknown>;
  if (v.version !== 1) throw new Error("Stored signing key has an unsupported version");
  if (typeof v.keyId !== "string" || !SAFE_IDENTIFIER_PATTERN.test(v.keyId)) throw new Error("Stored signing key has an invalid keyId");
  if (typeof v.domain !== "string" || publicHostname(v.domain) !== v.domain) throw new Error("Stored signing key has an invalid domain");
  if (
    typeof v.privateKeyPkcs8Base64 !== "string" ||
    v.privateKeyPkcs8Base64.length > MAX_PKCS8_BASE64_LENGTH ||
    !/^[A-Za-z0-9+/]+={0,2}$/.test(v.privateKeyPkcs8Base64)
  ) {
    throw new Error("Stored signing key has an invalid private key");
  }
  if (typeof v.createdAt !== "number" || !Number.isSafeInteger(v.createdAt) || v.createdAt < 0) {
    throw new Error("Stored signing key has an invalid createdAt");
  }
  return Object.freeze({
    version: 1,
    keyId: v.keyId,
    domain: v.domain,
    privateKeyPkcs8Base64: v.privateKeyPkcs8Base64,
    createdAt: v.createdAt,
  });
}

/**
 * Keeps the key in this process only. Every new process provisions (and registers) a new key, so use it for
 * tests and single long-lived processes, not for serverless or several instances.
 */
export function memoryKeyStore(initial: StoredSigningKey | null = null): KeyStore {
  let stored: StoredSigningKey | null = initial ? parseStoredSigningKey(initial) : null;
  return Object.freeze({
    load: () => stored,
    saveIfAbsent: (key: StoredSigningKey) => {
      if (stored) return false;
      stored = parseStoredSigningKey(key);
      return true;
    },
  });
}

/**
 * Read-only: the key `daywalker init` wrote to DAYWALKER_SIGNING_KEY, DAYWALKER_KEY_ID and DAYWALKER_DOMAIN.
 * It can't save, so a client using it never generates a key; set the variables with `daywalker init` (or
 * your secret manager) first.
 */
export function envKeyStore(env: Record<string, string | undefined> = typeof process !== "undefined" ? process.env : {}): KeyStore {
  return Object.freeze({
    load: (): StoredSigningKey | null => {
      const raw = env.DAYWALKER_SIGNING_KEY?.trim();
      if (!raw) return null;
      return parseStoredSigningKey({
        version: 1,
        keyId: env.DAYWALKER_KEY_ID?.trim(),
        domain: publicHostname(env.DAYWALKER_DOMAIN ?? env.DAYWALKER_SIGNING_DOMAIN ?? ""),
        privateKeyPkcs8Base64: raw,
        createdAt: 0,
      });
    },
  });
}
