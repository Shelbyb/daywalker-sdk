import net from "node:net";
import { loadSigningKey, type SigningKey } from "./signing.js";

/**
 * Everything a service needs, read from its environment:
 *
 *   DAYWALKER_API_KEY          the service's Daywalker API token (srv_live_…)          required
 *   DAYWALKER_SERVICE_SLUG     the service it validates against (e.g. "sonalyze")       required
 *   DAYWALKER_SIGNING_KEY      Ed25519 private key from `daywalker init`                required for allowlisted tokens
 *   DAYWALKER_SIGNING_KEY_PREVIOUS  old key, still published during a rotation          optional
 *   DAYWALKER_DOMAIN           public hostname that serves /.well-known/daywalker-keys.json
 *                              (defaults to the hostname of APP_URL, NEXTAUTH_URL, …)
 *   DAYWALKER_AUTH_URL         defaults to https://auth.daywalker.dev
 */

export interface DaywalkerOptions {
  apiKey?: string;
  serviceSlug?: string;
  /** Private key (PEM or base64 DER) or an already loaded key. */
  signingKey?: string | SigningKey | null;
  previousSigningKey?: string | SigningKey | null;
  domain?: string;
  authUrl?: string;
  /** Override for tests or custom runtimes. */
  fetch?: typeof fetch;
  /** Request timeout in ms (default 5000). */
  timeoutMs?: number;
  /** How long a successful validation is cached, in ms (default 60000, 0 disables). */
  cacheTtlMs?: number;
  env?: Record<string, string | undefined>;
}

export interface ResolvedConfig {
  apiKey: string | null;
  serviceSlug: string | null;
  signingKey: SigningKey | null;
  previousSigningKey: SigningKey | null;
  domain: string | null;
  /** Where the domain came from, for diagnostics. */
  domainSource: string | null;
  authUrl: string;
  problems: string[];
}

// Platform variables that commonly hold the app's public URL or hostname, in priority order
const URL_ENV_VARS = [
  "APP_URL",
  "NEXTAUTH_URL",
  "NEXT_PUBLIC_APP_URL",
  "BETTER_AUTH_URL",
  "PUBLIC_URL",
  "SITE_URL",
  "URL", // Netlify
  "VERCEL_PROJECT_PRODUCTION_URL",
  "RENDER_EXTERNAL_HOSTNAME",
  "RAILWAY_PUBLIC_DOMAIN",
  "VERCEL_URL",
];

const DOMAIN_PATTERN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/;

/**
 * A public hostname from a URL or bare host, or null for anything that can't be fetched over
 * the internet (localhost, 0.0.0.0, IP addresses, single labels). Containers often report their
 * bind address (http://0.0.0.0:3000) as the request origin, which must never be used.
 */
export function publicHostname(value: string | undefined | null): string | null {
  if (!value || !value.trim()) return null;
  let host = value.trim().toLowerCase();
  try {
    host = new URL(/^[a-z][a-z0-9+.-]*:\/\//.test(host) ? host : `https://${host}`).hostname;
  } catch {
    return null;
  }
  host = host.replace(/\.$/, "");
  if (net.isIP(host.replace(/^\[|\]$/g, "")) || host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local")) {
    return null;
  }
  return DOMAIN_PATTERN.test(host) ? host : null;
}

function keyFrom(value: string | SigningKey | null | undefined, name: string, problems: string[]): SigningKey | null {
  if (!value) return null;
  if (typeof value !== "string") return value;
  try {
    return loadSigningKey(value);
  } catch (err) {
    problems.push(`${name} could not be loaded: ${(err as Error).message}`);
    return null;
  }
}

export function resolveConfig(options: DaywalkerOptions = {}): ResolvedConfig {
  const env = options.env ?? process.env;
  const problems: string[] = [];

  const apiKey = (options.apiKey ?? env.DAYWALKER_API_KEY ?? "").trim() || null;
  const serviceSlug = (options.serviceSlug ?? env.DAYWALKER_SERVICE_SLUG ?? "").trim().toLowerCase() || null;
  if (!apiKey) problems.push("DAYWALKER_API_KEY is not set");
  if (!serviceSlug) problems.push("DAYWALKER_SERVICE_SLUG is not set");

  const signingKey = keyFrom(options.signingKey ?? env.DAYWALKER_SIGNING_KEY, "DAYWALKER_SIGNING_KEY", problems);
  const previousSigningKey = keyFrom(
    options.previousSigningKey ?? env.DAYWALKER_SIGNING_KEY_PREVIOUS,
    "DAYWALKER_SIGNING_KEY_PREVIOUS",
    problems
  );

  let domain: string | null = null;
  let domainSource: string | null = null;
  const explicit = options.domain ?? env.DAYWALKER_DOMAIN ?? env.DAYWALKER_SIGNING_DOMAIN;
  if (explicit) {
    domain = publicHostname(explicit);
    domainSource = options.domain ? "options.domain" : env.DAYWALKER_DOMAIN ? "DAYWALKER_DOMAIN" : "DAYWALKER_SIGNING_DOMAIN";
    if (!domain) problems.push(`${domainSource} (${explicit}) is not a public domain name`);
  } else {
    for (const name of URL_ENV_VARS) {
      const host = publicHostname(env[name]);
      if (host) {
        domain = host;
        domainSource = name;
        break;
      }
    }
  }
  if (signingKey && !domain) {
    problems.push("No public domain found: set DAYWALKER_DOMAIN (requests will be sent unsigned)");
  }

  const authUrl = (options.authUrl ?? env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");
  return { apiKey, serviceSlug, signingKey, previousSigningKey, domain, domainSource, authUrl, problems };
}
