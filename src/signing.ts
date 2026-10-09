import crypto, { type KeyObject } from "node:crypto";

/**
 * Domain-signed requests to Daywalker Auth.
 *
 * Each request is signed with an Ed25519 key whose public half the calling service serves at
 * https://<domain>/.well-known/daywalker-keys.json. Daywalker fetches that key over HTTPS, so
 * a valid signature proves the request comes from whoever controls the domain, wherever the
 * service is hosted. This must match Daywalker's verifier exactly (src/lib/request-signature.ts
 * in daywalker-service-auth).
 */

export const SIGNATURE_VERSION = "daywalker-v1";
export const KEYS_PATH = "/.well-known/daywalker-keys.json";

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  use: "sig";
  alg: "EdDSA";
}

export interface SigningKey {
  privateKey: KeyObject;
  publicJwk: PublicJwk;
}

/** Generate a new key; `privateKey` is base64 PKCS#8 DER, the format DAYWALKER_SIGNING_KEY expects. */
export function generateSigningKey(): { privateKey: string; publicJwk: PublicJwk } {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const der = privateKey.export({ format: "der", type: "pkcs8" }).toString("base64");
  return { privateKey: der, publicJwk: loadSigningKey(der).publicJwk };
}

/**
 * Load a private key from env: PKCS#8 PEM (literal "\n" escapes are fine) or base64 PKCS#8 DER.
 * The key id is the RFC 7638 JWK thumbprint, so it's stable without extra configuration.
 */
export function loadSigningKey(raw: string): SigningKey {
  const value = raw.trim();
  const privateKey = value.includes("-----BEGIN")
    ? crypto.createPrivateKey(value.replace(/\\n/g, "\n"))
    : crypto.createPrivateKey({ key: Buffer.from(value, "base64"), format: "der", type: "pkcs8" });
  if (privateKey.asymmetricKeyType !== "ed25519") {
    throw new Error(`DAYWALKER_SIGNING_KEY must be an Ed25519 key (got ${privateKey.asymmetricKeyType})`);
  }
  const { x } = crypto.createPublicKey(privateKey).export({ format: "jwk" }) as { x: string };
  const kid = crypto.createHash("sha256").update(JSON.stringify({ crv: "Ed25519", kty: "OKP", x })).digest("base64url");
  return { privateKey, publicJwk: { kty: "OKP", crv: "Ed25519", x, kid, use: "sig", alg: "EdDSA" } };
}

export function canonicalPayload(p: {
  method: string;
  path: string;
  domain: string;
  timestamp: string;
  nonce: string;
  body: string;
}): string {
  const bodySha256 = crypto.createHash("sha256").update(p.body, "utf8").digest("hex");
  return [SIGNATURE_VERSION, p.method.toUpperCase(), p.path, p.domain.toLowerCase(), p.timestamp, p.nonce, bodySha256].join(
    "\n"
  );
}

/** The X-Daywalker-* headers for one request. Send exactly `body` as the request body. */
export function signRequest(params: {
  method: string;
  /** URL path only, e.g. /api/v1/tokens/validate */
  path: string;
  domain: string;
  body: string;
  key: SigningKey;
  timestamp?: number;
  nonce?: string;
}): Record<string, string> {
  const timestamp = String(params.timestamp ?? Math.floor(Date.now() / 1000));
  const nonce = params.nonce ?? crypto.randomBytes(24).toString("base64url");
  const payload = canonicalPayload({ ...params, timestamp, nonce });
  return {
    "X-Daywalker-Domain": params.domain.toLowerCase(),
    "X-Daywalker-Key-Id": params.key.publicJwk.kid,
    "X-Daywalker-Timestamp": timestamp,
    "X-Daywalker-Nonce": nonce,
    "X-Daywalker-Signature": crypto.sign(null, Buffer.from(payload), params.key.privateKey).toString("base64url"),
  };
}
