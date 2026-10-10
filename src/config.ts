import type { DaywalkerConfig, PublicJwk, SigningKey } from "./types.js";

export interface ResolvedConfig {
  apiKey: string | null;
  signingKey: string | SigningKey | null;
  previousSigningKey: string | SigningKey | null;
  keyId: string | null;
  serviceSlug: string | null;
  domain: string | null;
  domainSource: string | null;
  daywalkerPublicKey: string | PublicJwk | null;
  authUrl: string;
  cacheTtlMs: number;
  negativeCacheTtlMs: number;
  maxRetries: number;
  problems: string[];
}

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

export function resolveConfig(options: DaywalkerConfig = {}): ResolvedConfig {
  const env: Record<string, string | undefined> =
    options.env ?? (typeof process !== "undefined" && process.env ? process.env : {});
  const problems: string[] = [];

  const apiKey = (options.apiKey ?? env.DAYWALKER_API_KEY ?? "").trim() || null;
  const serviceSlug = (options.serviceSlug ?? env.DAYWALKER_SERVICE_SLUG ?? "").trim().toLowerCase() || null;
  if (!apiKey) problems.push("DAYWALKER_API_KEY is not set");
  if (!serviceSlug) problems.push("DAYWALKER_SERVICE_SLUG is not set");

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
  const authUrl = (options.authUrl ?? env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");
  const cacheTtlMs = options.cacheTtlMs ?? 60_000;
  const negativeCacheTtlMs = options.negativeCacheTtlMs ?? 3_000;
  const maxRetries = options.maxRetries ?? (options.retry?.maxRetries ?? 3);

  return {
    apiKey,
    signingKey,
    previousSigningKey,
    keyId,
    serviceSlug,
    domain,
    domainSource,
    daywalkerPublicKey,
    authUrl,
    cacheTtlMs,
    negativeCacheTtlMs,
    maxRetries,
    problems,
  };
}
