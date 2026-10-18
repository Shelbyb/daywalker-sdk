export {
  stringToUtf8,
  utf8ToString,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  base64UrlToBytesStrict,
  bytesToHex,
  hexToBytes,
  timingSafeEqual,
  timingSafeEqualString,
  maskSecret,
  redactSecrets,
} from "./encoding.js";

export {
  DEFAULT_MAX_BODY_SIZE_BYTES,
  computeContentDigest,
  sha256Base64,
  sha256Base64Url,
} from "./digest.js";

export {
  calculateJwkThumbprint,
  generateSigningKey,
  loadSigningKey,
  loadPublicKey,
  importSigningKey,
} from "./keys.js";

export {
  SIGNATURE_VERSION,
  SIGNATURE_LABEL,
  SIGNATURE_ALG,
  MAX_CLOCK_SKEW_SECONDS,
  REPLAY_CACHE_MAX_ENTRIES,
  SignatureReplayCache,
  formatSignatureParams,
  createSignatureBase,
  signRequest,
  verifyRequestSignature,
  verifyJwtLease,
  leaseServices,
  SERVICE_SLUG_PATTERN,
  API_KEY_PATTERN,
} from "./signatures.js";

export {
  registerPublicKey,
  listSigningKeys,
  revokeSigningKey,
  keySlotFor,
  randomInstanceId,
  INSTANCE_ID_PATTERN,
  MIN_KEY_TTL_SECONDS,
  MAX_KEY_TTL_SECONDS,
} from "./key-api.js";
export type { SigningKeyRecord, KeyApiResult } from "./key-api.js";

export type {
  SignedHeaders,
  SignRequestParams,
  VerifySignatureParams,
  VerifySignatureResult,
  ReplayStore,
} from "./signatures.js";

export { generateDpopKey, createDpopProof, verifyDpopProof, globalDpopReplayCache, MAX_DPOP_PROOF_LENGTH, DPOP_MAX_AGE_SECONDS } from "./dpop.js";
export type { DpopKey, VerifyDpopProofParams } from "./dpop.js";
