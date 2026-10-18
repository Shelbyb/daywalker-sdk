export {
  Daywalker,
  createDaywalker,
  daywalker,
  MAX_RETRY_AFTER_MS,
  MAX_VALIDATION_CACHE_ENTRIES,
  MAX_CACHE_TTL_MS,
  MAX_TOKEN_LENGTH,
  JWKS_CACHE_TTL_MS,
  JWKS_REFETCH_COOLDOWN_MS,
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
  IncomingDpop,
  ValidateTokenOptions,
  ValidateErrorCode,
  ValidateResult,
  RetryOptions,
  SelfCheckResult,
  TokenSet,
  GetTokensOptions,
  AccessTokenUser,
  KeyStore,
  StoredSigningKey,
  MessageSigner,
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
  importSigningKey,
  formatSignatureParams,
  createSignatureBase,
  signRequest,
  verifyRequestSignature,
  verifyJwtLease,
  leaseServices,
  registerPublicKey,
  listSigningKeys,
  revokeSigningKey,
  keySlotFor,
  MIN_KEY_TTL_SECONDS,
  MAX_KEY_TTL_SECONDS,
  verifyDpopProof,
  MAX_DPOP_PROOF_LENGTH,
  DPOP_MAX_AGE_SECONDS,
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
  VerifyDpopProofParams,
  SigningKeyRecord,
  KeyApiResult,
} from "./crypto/index.js";

export { buildTokenCookie, clearTokenCookie, daywalkerCookies, accessTokenUser } from "./cookies.js";
export type { TokenCookieOptions } from "./cookies.js";
