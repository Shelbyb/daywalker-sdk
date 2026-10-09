export {
  stringToUtf8,
  utf8ToString,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  bytesToHex,
  hexToBytes,
  computeContentDigest,
  sha256Base64,
  sha256Base64Url,
  calculateJwkThumbprint,
  generateSigningKey,
  loadSigningKey,
  loadPublicKey,
  SIGNATURE_VERSION,
  SIGNATURE_LABEL,
  SIGNATURE_ALG,
  MAX_CLOCK_SKEW_SECONDS,
  formatSignatureParams,
  createSignatureBase,
  signRequest,
  verifyRequestSignature,
  verifyJwtLease,
  registerPublicKey,
} from "./crypto/index.js";

export const KEYS_PATH = "/.well-known/daywalker-keys.json";

export type {
  PublicJwk,
  SigningKey,
  SignedHeaders,
  SignRequestParams,
  VerifySignatureParams,
  VerifySignatureResult,
} from "./types.js";
