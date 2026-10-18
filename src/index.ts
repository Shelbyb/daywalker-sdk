export {
  Daywalker,
  createDaywalker,
  daywalker,
  MAX_RETRY_AFTER_MS,
  MAX_VALIDATION_CACHE_ENTRIES,
} from "./client.js";

export type {
  DaywalkerFetchInit,
} from "./client.js";

export {
  DaywalkerError,
  DaywalkerAuthError,
  DaywalkerRateLimitError,
  UNAVAILABLE_ERROR_CODES,
} from "./types.js";

export type {
  DaywalkerConfig,
  RateLimitWindow,
  TokenPayload,
  ValidateErrorCode,
  ValidateResult,
  RetryOptions,
  SelfCheckResult,
  LeaseResponse,
  IssueLeaseOptions,
  PublicJwk,
  PublicJwks,
  SigningKey,
} from "./types.js";

export {
  resolveConfig,
  parseServiceSlugs,
  publicHostname,
  assertSecureUrl,
  DEFAULT_TIMEOUT_MS,
} from "./config.js";

export type {
  ResolvedConfig,
} from "./config.js";

export {
  SIGNATURE_VERSION,
  SIGNATURE_LABEL,
  SIGNATURE_ALG,
  MAX_CLOCK_SKEW_SECONDS,
  REPLAY_CACHE_MAX_ENTRIES,
  SignatureReplayCache,
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
  leaseServices,
  registerPublicKey,
  stringToUtf8,
  utf8ToString,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64Url,
  base64UrlToBytes,
  base64UrlToBytesStrict,
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
  ReplayStore,
} from "./crypto/index.js";
