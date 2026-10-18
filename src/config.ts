import type { DaywalkerConfig, PublicJwk, PublicJwks, RetryOptions, SigningKey } from "./types.js";

export interface ResolvedConfig {
  apiKey: string | null;
  signingKey: string | SigningKey | null;
  /** Never signs; `keys()` publishes its public JWK alongside the current key during rotation. */
  previousSigningKey: string | SigningKey | null;
  keyId: string | null;
  /** The slug used when a call doesn't name one: the first of `serviceSlugs`. */
  serviceSlug: string | null;
  /** Every service this deployment is configured for (one API key can cover several). */
  serviceSlugs: string[];
  domain: string | null;
  domainSource: string | null;
  daywalkerPublicKey: string | PublicJwk | PublicJwks | null;
  /** "auto": offline verification keys come from `${authUrl}/.well-known/jwks.json` (env DAYWALKER_JWKS). */
  jwks: "auto" | null;
  leaseIssuer: string | null;
  /** Ephemeral signing keys, when enabled: their lifetime and this process's key slot (null = random). */
  ephemeralKey: { ttlSeconds: number; instanceId: string | null } | null;
  /** Origin clients use to reach this service, for DPoP `htu` checks (env DAYWALKER_PUBLIC_ORIGIN). */
  publicOrigin: string | null;
  authUrl: string;
  cacheTtlMs: number;
  negativeCacheTtlMs: number;
  maxRetries: number;
  /** `config.retry` with undefined fields dropped; per-request `init.retry` is layered on top. */
  retry: RetryOptions;
  timeoutMs: number;
  problems: string[];
}

/** Default lifetime of an ephemeral signing key (6 hours); it is replaced when a quarter of that is left. */
export const DEFAULT_EPHEMERAL_KEY_TTL_SECONDS = 21_600;

/** Default per-attempt timeout for requests to Daywalker Auth. */
export const DEFAULT_TIMEOUT_MS = 5_000;

const URL_ENV_VARS = [
  "APP_URL",
  "NEXTAUTH_URL",
  "NEXT_PUBLIC_APP_URL",
  "BETTER_AUTH_URL",
  "PUBLIC_URL",
  "SITE_URL",
  "URL",
  "VERCEL_PROJECT_PRODUCTION_URL",
  "RENDER_EXTERNAL_HOSTNAME",
  "RAILWAY_PUBLIC_DOMAIN",
  "VERCEL_URL",
];

const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

function isIpAddress(host: string): boolean {
  if (host.length > 253) return false;
  // IPv4
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(host)) return true;
  // IPv6
  if (host.includes(":")) return true;
  return false;
}

/**
 * A public hostname from a URL or bare host, or null for anything that can't be fetched over
 * the internet (localhost, 0.0.0.0, IP addresses, single labels).
 */
export function publicHostname(value: string | undefined | null): string | null {
  if (!value || !value.trim()) return null;
  let host = value.trim().toLowerCase();
  if (host.length > 253) return null;
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(host) ? host : `https://${host}`).hostname;
  } catch {
    return null;
  }
  host = host.replace(/\.$/, "");
  if (host.length > 253 || isIpAddress(host.replace(/^\[|\]$/g, "")) || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    return null;
  }
  return DOMAIN_PATTERN.test(host) ? host : null;
}

const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Throws unless `value` is an https: URL (http: is allowed only for localhost / 127.0.0.1 / [::1]),
 * so API keys, access tokens, SDK keys and write keys never travel in cleartext.
 */
export function assertSecureUrl(name: string, value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${name} must be an absolute https:// URL (got "${value}")`);
  }
  if (url.username || url.password) {
    throw new Error(`${name} must not contain credentials`);
  }
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) return;
  throw new Error(`${name} must use https:// (http:// is only allowed for localhost); got "${value}"`);
}

/**
 * Service slugs from a comma- or whitespace-separated string (`DAYWALKER_SERVICE_SLUG="gigpulse,devpulse"`)
 * or an array: lower-cased, de-duplicated, in the order given (the first is the default service).
 */
export function parseServiceSlugs(value: string | readonly string[] | null | undefined): string[] {
  const parts = typeof value === "string" ? value.split(/[\s,]+/) : Array.isArray(value) ? value.flatMap((v) => String(v).split(/[\s,]+/)) : [];
  return Array.from(new Set(parts.map((v) => v.trim().toLowerCase()).filter(Boolean)));
}

export function resolveConfig(options: DaywalkerConfig = {}): ResolvedConfig {
  const env: Record<string, string | undefined> =
    options.env ?? (typeof process !== "undefined" && process.env ? process.env : {});
  const problems: string[] = [];

  const apiKey = (options.apiKey ?? env.DAYWALKER_API_KEY ?? "").trim() || null;
  const serviceSlugs = parseServiceSlugs(options.serviceSlugs ?? options.serviceSlug ?? env.DAYWALKER_SERVICE_SLUG);
  const serviceSlug = serviceSlugs[0] ?? null;
  if (!apiKey) problems.push("DAYWALKER_API_KEY is not set: it is the client credential for the OAuth client credentials grant");

  const signingKey = options.signingKey ?? env.DAYWALKER_SIGNING_KEY ?? null;
  const previousSigningKey = options.previousSigningKey ?? env.DAYWALKER_SIGNING_KEY_PREVIOUS ?? null;
  const keyId = (options.keyId ?? env.DAYWALKER_KEY_ID ?? "").trim() || null;

  let domain: string | null = null;
  let domainSource: string | null = null;
  const explicit = options.domain ?? env.DAYWALKER_DOMAIN ?? env.DAYWALKER_SIGNING_DOMAIN;
  if (explicit) {
    domain = publicHostname(explicit);
    domainSource = options.domain ? "options.domain" : env.DAYWALKER_DOMAIN ? "DAYWALKER_DOMAIN" : "DAYWALKER_SIGNING_DOMAIN";
    if (!domain) problems.push(`${domainSource} (${explicit}) is not a public domain name`);
  } else {
    for (const name of URL_ENV_VARS) {
      const val = env[name];
      if (val) {
        const host = publicHostname(val);
        if (host) {
          domain = host;
          domainSource = name;
          break;
        }
      }
    }
  }

  const daywalkerPublicKey = options.daywalkerPublicKey ?? (env.DAYWALKER_PUBLIC_KEY ? env.DAYWALKER_PUBLIC_KEY.trim() : null);
  const rawJwks = String(options.jwks ?? env.DAYWALKER_JWKS ?? "").trim().toLowerCase();
  const jwks = rawJwks === "auto" ? "auto" : null;
  if (rawJwks && rawJwks !== "auto" && rawJwks !== "off") problems.push(`DAYWALKER_JWKS must be "auto" or "off" (got "${rawJwks.slice(0, 40)}"); JWKS fetching is off`);
  const leaseIssuer = (options.leaseIssuer ?? env.DAYWALKER_LEASE_ISSUER ?? "").trim() || null;
  let ephemeralKey: ResolvedConfig["ephemeralKey"] = null;
  const ephemeralOption = options.ephemeralKey ?? (/^(1|true|yes)$/i.test(env.DAYWALKER_EPHEMERAL_KEY ?? "") ? true : undefined);
  if (ephemeralOption) {
    const o = typeof ephemeralOption === "object" ? ephemeralOption : {};
    const ttlSeconds = o.ttlSeconds ?? (env.DAYWALKER_KEY_TTL_SECONDS ? Number(env.DAYWALKER_KEY_TTL_SECONDS) : DEFAULT_EPHEMERAL_KEY_TTL_SECONDS);
    if (!Number.isInteger(ttlSeconds) || ttlSeconds < 3_600 || ttlSeconds > 2_592_000) {
      throw new Error(`ephemeralKey.ttlSeconds must be a whole number of seconds from 3600 to 2592000 (got ${ttlSeconds})`);
    }
    const instanceId = (o.instanceId ?? env.DAYWALKER_INSTANCE_ID ?? "").trim() || null;
    if (instanceId !== null && !/^[A-Za-z0-9_.-]{1,64}$/.test(instanceId)) {
      throw new Error("ephemeralKey.instanceId must be 1-64 of A-Z a-z 0-9 . _ -");
    }
    ephemeralKey = { ttlSeconds, instanceId };
  }

  const rawPublicOrigin = (options.publicOrigin ?? env.DAYWALKER_PUBLIC_ORIGIN ?? "").trim();
  let publicOrigin: string | null = null;
  if (rawPublicOrigin) {
    assertSecureUrl("publicOrigin", rawPublicOrigin);
    publicOrigin = new URL(rawPublicOrigin).origin;
  }
  const authUrl = (options.authUrl ?? env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");
  assertSecureUrl("authUrl", authUrl);
  const cacheTtlMs = options.cacheTtlMs ?? 60_000;
  const negativeCacheTtlMs = options.negativeCacheTtlMs ?? 3_000;
  const maxRetries = options.maxRetries ?? (options.retry?.maxRetries ?? 3);
  const retry: RetryOptions = {};
  for (const [k, v] of Object.entries(options.retry ?? {})) {
    if (v !== undefined) (retry as Record<string, unknown>)[k] = v;
  }
  retry.maxRetries = maxRetries;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  if (!Number.isFinite(timeoutMs) || timeoutMs < 0) {
    throw new Error(`timeoutMs must be a non-negative number of milliseconds (got ${timeoutMs})`);
  }

  return {
    apiKey,
    signingKey,
    previousSigningKey,
    keyId,
    serviceSlug,
    serviceSlugs,
    domain,
    domainSource,
    daywalkerPublicKey,
    jwks,
    leaseIssuer,
    ephemeralKey,
    publicOrigin,
    authUrl,
    cacheTtlMs,
    negativeCacheTtlMs,
    maxRetries,
    retry,
    timeoutMs,
    problems,
  };
}
