import { baseUrl, DevPulseHttpError, readText, retryAfterSeconds, send, userAgent, type HttpOptions } from "../common/http.js";

/**
 * Runtime secrets fetch: `GET {host}/api/v1/secrets` with a service token (`Authorization: Bearer
 * dps_…`) returns the token's environment with references resolved. Fetch only; nothing is cached
 * or written anywhere. To copy secrets into `process.env` on Node, use `@shelbyb/daywalker-sdk/secrets/env`.
 */

export type SecretsOptions = HttpOptions & {
  /** Your DevPulse URL, e.g. https://devpulse.example.com. */
  host: string;
  /** A service token (`dps_…`). Sent only in the Authorization header. */
  token: string;
  signal?: AbortSignal;
};

export type SecretsResult = {
  /** Key/value pairs of the token's environment. */
  secrets: Record<string, string>;
  /** The environment the token belongs to, when DevPulse reports it. */
  environment?: string;
  /** References that could not be resolved, as "KEY: reason". */
  warnings: string[];
};

/** Responses over this size are refused (DevPulse environments are far smaller). */
const MAX_RESPONSE_CHARS = 4 * 1024 * 1024;

async function get(options: SecretsOptions, format: "json" | "dotenv"): Promise<string> {
  const host = baseUrl("host", options.host);
  if (!options.token) throw new Error("token is required");
  const res = await send(
    `${host}/api/v1/secrets?format=${format}`,
    { method: "GET", headers: { authorization: `Bearer ${options.token}`, accept: format === "json" ? "application/json" : "text/plain", "user-agent": userAgent("Secrets") } },
    options,
  );
  if (!res.ok) throw new DevPulseHttpError("Secrets fetch", res.status, await readText(res, 500), retryAfterSeconds(res));
  const text = await res.text();
  if (text.length > MAX_RESPONSE_CHARS) throw new Error("Secrets response is too large");
  return text;
}

/** Fetch the token's secrets as an object. Throws `DevPulseHttpError` (401 bad token, 403 IP not allowed, 429). */
export async function fetchSecrets(options: SecretsOptions): Promise<SecretsResult> {
  const text = await get(options, "json");
  let json: { secrets?: Record<string, unknown>; environment?: unknown; warnings?: unknown };
  try {
    json = JSON.parse(text);
  } catch {
    // Not rethrown: V8's SyntaxError message quotes part of the input, i.e. secret values.
    throw new Error("Secrets response is not valid JSON");
  }
  if (!json || typeof json.secrets !== "object" || json.secrets === null) throw new Error("Unexpected secrets response");
  const secrets: Record<string, string> = Object.create(null);
  for (const [k, v] of Object.entries(json.secrets)) if (typeof v === "string") secrets[k] = v;
  return {
    secrets,
    environment: typeof json.environment === "string" ? json.environment : undefined,
    warnings: Array.isArray(json.warnings) ? json.warnings.filter((w): w is string => typeof w === "string") : [],
  };
}

/** Fetch the token's secrets as dotenv text (KEY="value" lines). */
export function fetchDotenv(options: SecretsOptions): Promise<string> {
  return get(options, "dotenv");
}

/** Parse dotenv text (KEY=value, optional `export`, single/double quotes, # comments, \n escapes in double quotes). */
export function parseDotenv(text: string): Record<string, string> {
  const out: Record<string, string> = Object.create(null);
  const re = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_.-]*)[ \t]*=[ \t]*('(?:[^'])*'|"(?:\\.|[^"\\])*"|[^\r\n]*)[ \t]*(?:#[^\r\n]*)?$/gm;
  for (const m of text.matchAll(re)) {
    let v = m[2]!;
    if (v.startsWith("'")) v = v.slice(1, -1);
    else if (v.startsWith('"')) v = v.slice(1, -1).replace(/\\([nrt"\\$])/g, (_, c: string) => ({ n: "\n", r: "\r", t: "\t" })[c] ?? c);
    else v = v.replace(/\s+#.*$/, "").trim();
    out[m[1]!] = v;
  }
  return out;
}
