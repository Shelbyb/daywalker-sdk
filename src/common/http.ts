import { assertSecureUrl } from "../secure-url.js";
import { SDK_VERSION } from "../flags/common/version.js";

/** Shared fetch plumbing for the small ingest clients (cron, logs, secrets, oncall). Portable: fetch only. */

export type HttpOptions = {
  /** Per-request timeout in ms. Default 10000; 0 disables. */
  timeoutMs?: number;
  fetch?: typeof fetch;
};

/** A non-2xx response from a DevPulse ingest endpoint. */
export class DevPulseHttpError extends Error {
  readonly status: number;
  readonly body: string;
  /** Seconds from Retry-After, when sent. */
  readonly retryAfter?: number;
  constructor(what: string, status: number, body: string, retryAfter?: number) {
    super(`${what} failed (HTTP ${status})${body ? `: ${body.slice(0, 200)}` : ""}`);
    this.name = "DevPulseHttpError";
    this.status = status;
    this.body = body;
    this.retryAfter = retryAfter;
  }
}

/** Validate and normalize a DevPulse base URL (https only, except localhost; no credentials). */
export function baseUrl(name: string, value: string | undefined): string {
  if (!value) throw new Error(`${name} is required`);
  assertSecureUrl(name, value);
  return value.replace(/\/+$/, "");
}

export const userAgent = (kind: string) => `DevPulse${kind}/${SDK_VERSION}`;

/** fetch with a timeout, no redirects (so credentials never follow a 3xx) and an optional caller signal. */
export async function send(url: string, init: RequestInit, o: HttpOptions & { signal?: AbortSignal }): Promise<Response> {
  const ms = o.timeoutMs ?? 10_000;
  const timeout = ms ? AbortSignal.timeout(ms) : undefined;
  const signal = o.signal && timeout ? AbortSignal.any([o.signal, timeout]) : (o.signal ?? timeout);
  return (o.fetch ?? globalThis.fetch)(url, { ...init, signal, redirect: "error", cache: "no-store" } as RequestInit);
}

/** Read at most `max` characters of a response body (for error messages). */
export async function readText(res: Response, max = 2000): Promise<string> {
  try {
    return (await res.text()).slice(0, max);
  } catch {
    return "";
  }
}

export function retryAfterSeconds(res: Response): number | undefined {
  const v = res.headers.get("retry-after");
  return v && /^\d+$/.test(v.trim()) ? Number(v.trim()) : undefined;
}

/** UTF-8 byte length without Buffer. */
export const byteLength = (s: string) => new TextEncoder().encode(s).length;
