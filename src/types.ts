import { redactSecrets } from "./crypto/encoding.js";

export interface RateLimitWindow {
  limit: number;
  remaining: number;
  reset: number;
}

export interface TokenPayload {
  serviceSlug: string;
  tenantId: string;
  rateLimit: RateLimitWindow;
  rateLimitHourly?: RateLimitWindow;
  tokenId?: string;
  tokenName?: string;
  userId?: string;
  stage?: string;
  offlineVerified?: boolean;
  [key: string]: unknown;
}

export type ValidateErrorCode =
  | "EXPIRED"
  | "REVOKED"
  | "INVALID_TOKEN"
  | "RATE_LIMITED"
  | "NETWORK_ERROR"
  | "CONFIGURATION_ERROR"
  | string;

export type ValidateResult =
  | {
      ok: true;
      data: TokenPayload;
    }
  | {
      ok: false;
      error: ValidateErrorCode;
      status: number;
      message: string;
      retryAfter?: number;
    };

export interface PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  use?: "sig";
  alg?: "EdDSA" | "ed25519";
}

export interface SigningKey {
  privateKey: CryptoKey;
  publicKey: CryptoKey;
  publicJwk: PublicJwk;
  privateKeyPkcs8Base64?: string;
}

export interface RetryOptions {
  maxRetries?: number;
  initialDelayMs?: number;
  maxDelayMs?: number;
  backoffFactor?: number;
  jitter?: boolean;
}

export interface DaywalkerConfig {
  apiKey?: string;
  signingKey?: string | SigningKey;
  previousSigningKey?: string | SigningKey;
  keyId?: string;
  serviceSlug?: string;
  domain?: string;
  daywalkerPublicKey?: string | PublicJwk;
  /** Expected `iss` of offline-verified JWT leases (env DAYWALKER_LEASE_ISSUER). Unchecked when unset. */
  leaseIssuer?: string;
  /** Must be https:// (http:// only for localhost). */
  authUrl?: string;
  cacheTtlMs?: number;
  /** Short cache for failed validations (not 429/network errors). Default 3000ms; 0 disables. */
  negativeCacheTtlMs?: number;
  maxRetries?: number;
  retry?: RetryOptions;
  fetch?: typeof fetch;
  env?: Record<string, string | undefined>;
}

export interface SelfCheckResult {
  ok: boolean;
  serviceSlug: string | null;
  domain: string | null;
  signing: boolean;
  keyId: string | null;
  offlineVerificationReady: boolean;
  problems: string[];
}

export interface SignedHeaders {
  "Content-Digest"?: string;
  "Signature-Input": string;
  Signature: string;
  Authorization?: string;
  [key: string]: string | undefined;
}

export interface SignRequestParams {
  method: string;
  path: string;
  authority: string;
  body?: string | Uint8Array | null;
  key: SigningKey | string;
  created?: number;
  keyid?: string;
  alg?: string;
  apiKey?: string;
  nonce?: string;
}

export interface VerifySignatureParams {
  method: string;
  path: string;
  authority: string;
  headers: Record<string, string | undefined> | Headers;
  body?: string | Uint8Array | null;
  publicKey: PublicJwk | CryptoKey | string;
  currentTime?: number;
  maxClockSkewSeconds?: number;
  replayCheck?: boolean;
}

export interface VerifySignatureResult {
  valid: boolean;
  keyid?: string;
  error?: string;
}

export class DaywalkerError extends Error {
  public readonly status?: number;
  public readonly code?: string;

  constructor(message: string, status?: number, code?: string) {
    const cleanMessage = redactSecrets(message);
    super(cleanMessage);
    this.name = "DaywalkerError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  public toJSON(): Record<string, unknown> {
    return {
      name: this.name,
      message: redactSecrets(this.message),
      status: this.status,
      code: this.code,
    };
  }

  public [Symbol.for("nodejs.util.inspect.custom")](): Record<string, unknown> {
    return this.toJSON();
  }
}

export class DaywalkerAuthError extends DaywalkerError {
  constructor(message: string, status = 401, code: ValidateErrorCode = "INVALID_TOKEN") {
    super(message, status, code);
    this.name = "DaywalkerAuthError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

export class DaywalkerRateLimitError extends DaywalkerError {
  public readonly retryAfter?: number;

  constructor(message: string, retryAfter?: number) {
    super(message, 429, "RATE_LIMITED");
    this.name = "DaywalkerRateLimitError";
    this.retryAfter = retryAfter;
    Object.setPrototypeOf(this, new.target.prototype);
  }

  public override toJSON(): Record<string, unknown> {
    return {
      ...super.toJSON(),
      retryAfter: this.retryAfter,
    };
  }
}
