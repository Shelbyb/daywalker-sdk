import { webcrypto } from "./webcrypto.js";
import type { PublicJwk, PublicJwks, SigningKey } from "../types.js";
import {
  base64ToBytes,
  base64UrlToBytes,
  bytesToBase64,
  bytesToBase64Url,
  stringToUtf8,
} from "./encoding.js";
import { sha256Base64Url } from "./digest.js";

// PKCS#8 prefix for Ed25519 private keys (16 bytes)
// 30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20
const ED25519_PKCS8_PREFIX = new Uint8Array([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

// SPKI prefix for Ed25519 public keys (12 bytes)
// 30 2a 30 05 06 03 2b 65 70 03 21 00
const ED25519_SPKI_PREFIX = new Uint8Array([
  0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
]);

/**
 * Calculate the RFC 7638 JWK thumbprint for an Ed25519 public key.
 */
export async function calculateJwkThumbprint(jwk: {
  crv: string;
  kty: string;
  x: string;
}): Promise<string> {
  const canonical = JSON.stringify({ crv: jwk.crv, kty: jwk.kty, x: jwk.x });
  return sha256Base64Url(canonical);
}

/**
 * Generate a new Ed25519 keypair using WebCrypto.
 */
export async function generateSigningKey(): Promise<SigningKey> {
  const keyPair = (await webcrypto.generateKey("Ed25519", true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;

  const jwk = (await webcrypto.exportKey("jwk", keyPair.privateKey)) as {
    kty: "OKP";
    crv: "Ed25519";
    x: string;
    d?: string;
  };

  const pkcs8Buffer = await webcrypto.exportKey("pkcs8", keyPair.privateKey);
  const privateKeyPkcs8Base64 = bytesToBase64(new Uint8Array(pkcs8Buffer));

  const kid = await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x: jwk.x });
  const publicJwk: PublicJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x,
    kid,
    use: "sig",
    alg: "EdDSA",
  };

  return {
    privateKey: keyPair.privateKey,
    publicKey: keyPair.publicKey,
    publicJwk,
    privateKeyPkcs8Base64,
  };
}

/**
 * Load and import an Ed25519 private key from various string representations
 * (PKCS#8 Base64 DER, PKCS#8 PEM, Base64url raw seed, or JSON JWK).
 */
export async function loadSigningKey(raw: string | SigningKey): Promise<SigningKey> {
  if (typeof raw !== "string") {
    return raw;
  }

  const trimmed = raw.trim();

  // If raw string is JSON JWK
  if (trimmed.startsWith("{") && trimmed.endsWith("}")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed.kty === "OKP" && parsed.crv === "Ed25519" && parsed.d) {
        const privateKey = await webcrypto.importKey(
          "jwk",
          parsed,
          "Ed25519",
          true,
          ["sign"]
        );
        const jwk = (await webcrypto.exportKey("jwk", privateKey)) as {
          x: string;
        };
        const kid = parsed.kid || (await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x: jwk.x }));
        const publicJwk: PublicJwk = {
          kty: "OKP",
          crv: "Ed25519",
          x: jwk.x,
          kid,
          use: "sig",
          alg: "EdDSA",
        };
        const publicKey = await webcrypto.importKey(
          "jwk",
          { kty: "OKP", crv: "Ed25519", x: jwk.x },
          "Ed25519",
          true,
          ["verify"]
        );
        const pkcs8Buffer = await webcrypto.exportKey("pkcs8", privateKey);
        return {
          privateKey,
          publicKey,
          publicJwk,
          privateKeyPkcs8Base64: bytesToBase64(new Uint8Array(pkcs8Buffer)),
        };
      }
    } catch {
      // Continue to binary/PEM parsing
    }
  }

  // Handle PEM or Base64 / Base64url
  let cleaned = trimmed
    .replace(/-----BEGIN [A-Z0-9_-]+ PRIVATE KEY-----/gi, "")
    .replace(/-----END [A-Z0-9_-]+ PRIVATE KEY-----/gi, "")
    .replace(/\\n/g, "")
    .replace(/\s+/g, "");

  let keyBytes: Uint8Array;
  try {
    keyBytes = cleaned.includes("-") || cleaned.includes("_")
      ? base64UrlToBytes(cleaned)
      : base64ToBytes(cleaned);
  } catch {
    throw new Error("Invalid base64 encoding in signing key");
  }

  // If 32 bytes raw seed, wrap into standard PKCS#8 DER
  if (keyBytes.length === 32) {
    const pkcs8 = new Uint8Array(ED25519_PKCS8_PREFIX.length + 32);
    pkcs8.set(ED25519_PKCS8_PREFIX, 0);
    pkcs8.set(keyBytes, ED25519_PKCS8_PREFIX.length);
    keyBytes = pkcs8;
  }

  let privateKey: CryptoKey;
  try {
    privateKey = await webcrypto.importKey(
      "pkcs8",
      keyBytes as unknown as BufferSource,
      "Ed25519",
      true,
      ["sign"]
    );
  } catch (err) {
    throw new Error(`Failed to import Ed25519 private key: ${(err as Error).message}`);
  }

  const jwk = (await webcrypto.exportKey("jwk", privateKey)) as {
    x: string;
  };
  const kid = await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x: jwk.x });
  const publicJwk: PublicJwk = {
    kty: "OKP",
    crv: "Ed25519",
    x: jwk.x,
    kid,
    use: "sig",
    alg: "EdDSA",
  };

  const publicKey = await webcrypto.importKey(
    "jwk",
    { kty: "OKP", crv: "Ed25519", x: jwk.x },
    "Ed25519",
    true,
    ["verify"]
  );

  return {
    privateKey,
    publicKey,
    publicJwk,
    privateKeyPkcs8Base64: bytesToBase64(keyBytes),
  };
}

/**
 * Picks the Ed25519 key with this `kid` from a JWKS, or its only Ed25519 key (the signature check still
 * has to pass against it). Several keys and no matching `kid` is an error rather than a guess.
 */
function selectJwk(jwks: { keys?: unknown }, kid?: string): PublicJwk {
  const keys = (Array.isArray(jwks.keys) ? jwks.keys : []).filter(
    (k): k is PublicJwk => !!k && typeof k === "object" && (k as PublicJwk).kty === "OKP" && (k as PublicJwk).crv === "Ed25519"
  );
  const byKid = kid ? keys.find((k) => k.kid === kid) : undefined;
  if (byKid) return byKid;
  if (keys.length === 1) return keys[0];
  if (keys.length === 0) throw new Error("JWKS contains no Ed25519 keys");
  throw new Error(kid ? `No key in JWKS matches kid "${kid}"` : "JWKS has several keys and the signature names no kid");
}

/**
 * Load an Ed25519 public key from JWK, JWKS (selected by `kid`), PEM, Base64 SPKI, or Base64url raw public key.
 */
export async function loadPublicKey(
  raw: string | PublicJwk | PublicJwks | CryptoKey,
  kid?: string
): Promise<{ publicKey: CryptoKey; publicJwk: PublicJwk }> {
  if (typeof raw === "object" && raw && "keys" in raw) {
    return loadPublicKey(selectJwk(raw, kid));
  }
  if (typeof raw === "object" && "type" in raw && raw.type === "public") {
    const exported = (await webcrypto.exportKey("jwk", raw as CryptoKey)) as {
      x: string;
      kid?: string;
    };
    const kid = exported.kid || (await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x: exported.x }));
    return {
      publicKey: raw as CryptoKey,
      publicJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: exported.x,
        kid,
        use: "sig",
        alg: "EdDSA",
      },
    };
  }

  if (typeof raw === "object" && "kty" in raw && raw.kty === "OKP" && raw.crv === "Ed25519") {
    const kid = raw.kid || (await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x: raw.x }));
    const publicKey = await webcrypto.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", x: raw.x },
      "Ed25519",
      true,
      ["verify"]
    );
    return {
      publicKey,
      publicJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: raw.x,
        kid,
        use: "sig",
        alg: "EdDSA",
      },
    };
  }

  if (typeof raw !== "string") {
    throw new Error("Invalid public key format");
  }

  const trimmed = raw.trim();

  // Try parsing as JSON JWK or JWKS
  if (trimmed.startsWith("{")) {
    let parsed: any;
    try {
      parsed = JSON.parse(trimmed);
    } catch {
      // Continue
    }
    if (parsed && typeof parsed === "object") {
      const jwkCandidate = parsed.keys ? selectJwk(parsed, kid) : parsed;
      if (jwkCandidate.kty === "OKP" && jwkCandidate.crv === "Ed25519") {
        return loadPublicKey(jwkCandidate);
      }
    }
  }

  // Handle PEM / Base64 / Base64url
  let cleaned = trimmed
    .replace(/-----BEGIN [A-Z0-9_-]+ PUBLIC KEY-----/gi, "")
    .replace(/-----END [A-Z0-9_-]+ PUBLIC KEY-----/gi, "")
    .replace(/\\n/g, "")
    .replace(/\s+/g, "");

  let keyBytes: Uint8Array;
  try {
    keyBytes = cleaned.includes("-") || cleaned.includes("_")
      ? base64UrlToBytes(cleaned)
      : base64ToBytes(cleaned);
  } catch {
    throw new Error("Invalid base64 encoding in public key");
  }

  // If 32 bytes raw public key (x coord), import as JWK directly
  if (keyBytes.length === 32) {
    const x = bytesToBase64Url(keyBytes);
    const kid = await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x });
    const publicKey = await webcrypto.importKey(
      "jwk",
      { kty: "OKP", crv: "Ed25519", x },
      "Ed25519",
      true,
      ["verify"]
    );
    return {
      publicKey,
      publicJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x,
        kid,
        use: "sig",
        alg: "EdDSA",
      },
    };
  }

  // Try SPKI format
  try {
    const publicKey = await webcrypto.importKey(
      "spki",
      keyBytes as unknown as BufferSource,
      "Ed25519",
      true,
      ["verify"]
    );
    const jwk = (await webcrypto.exportKey("jwk", publicKey)) as {
      x: string;
    };
    const kid = await calculateJwkThumbprint({ crv: "Ed25519", kty: "OKP", x: jwk.x });
    return {
      publicKey,
      publicJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: jwk.x,
        kid,
        use: "sig",
        alg: "EdDSA",
      },
    };
  } catch (err) {
    throw new Error(`Failed to import public key: ${(err as Error).message}`);
  }
}
