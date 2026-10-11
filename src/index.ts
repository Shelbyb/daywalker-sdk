export {
  Daywalker,
  createDaywalker,
  daywalker,
} from "./client.js";

export {
  DaywalkerError,
  DaywalkerAuthError,
  DaywalkerRateLimitError,
} from "./types.js";

export type {
  DaywalkerConfig,
  RateLimitWindow,
  TokenPayload,
  ValidateErrorCode,
  ValidateResult,
  RetryOptions,
  SelfCheckResult,
  PublicJwk,
  SigningKey,
} from "./types.js";

export {
  resolveConfig,
  publicHostname,
  assertSecureUrl,
} from "./config.js";

export type {
  ResolvedConfig,
} from "./config.js";

export {
  SIGNATURE_VERSION,
  SIGNATURE_LABEL,
  SIGNATURE_ALG,
  MAX_CLOCK_SKEW_SECONDS,
  computeContentDigest,
  sha256Base64,
  sha256Base64Url,
  calculateJwkThumbprint,
  generateSigningKey,
  loadSigningKey,
  loadPublicKey,
  formatSignatureParams,
  createSignatureBase,
  signRequest,
  verifyRequestSignature,
  verifyJwtLease,
  registerPublicKey,
  stringToUtf8,
  utf8ToString,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  bytesToHex,
  hexToBytes,
  maskSecret,
  redactSecrets,
} from "./crypto/index.js";

export type {
  SignedHeaders,
  SignRequestParams,
  VerifySignatureParams,
  VerifySignatureResult,
} from "./crypto/index.js";
