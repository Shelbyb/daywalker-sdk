import { bytesToBase64Url, stringToUtf8 } from "./encoding.js";
import { sha256Base64Url } from "./digest.js";

/**
 * DPoP (RFC 9449) proof-of-possession. Daywalker binds every access and refresh token to a client key and
 * requires a fresh proof on each token request, refresh and validate call.
 */
export interface DpopKey {
  privateKey: CryptoKey;
  publicJwk: { kty: "OKP"; crv: "Ed25519"; x: string };
}

/** A new in-memory Ed25519 DPoP key. Tokens are bound to it, so keep it for the life of the session. */
export async function generateDpopKey(): Promise<DpopKey> {
  const pair = (await globalThis.crypto.subtle.generateKey({ name: "Ed25519" } as any, true, ["sign", "verify"])) as CryptoKeyPair;
  const jwk = (await globalThis.crypto.subtle.exportKey("jwk", pair.publicKey)) as { x: string };
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
    jti: globalThis.crypto.randomUUID(),
    htm: params.method.toUpperCase(),
    htu: `${u.origin}${u.pathname}`,
    iat: Math.floor(Date.now() / 1000),
  };
  if (params.accessToken) claims.ath = await sha256Base64Url(params.accessToken);
  const signingInput = `${b64u(header)}.${b64u(claims)}`;
  const sig = new Uint8Array(await globalThis.crypto.subtle.sign({ name: "Ed25519" } as any, key.privateKey, stringToUtf8(signingInput) as BufferSource));
  return `${signingInput}.${bytesToBase64Url(sig)}`;
}
