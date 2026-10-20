import { assertSecureUrl } from "../secure-url.js";

export const DEFAULT_AUTH_URL = "https://auth.daywalker.dev";
/** Per-attempt timeout for onboarding calls. */
export const ONBOARD_API_TIMEOUT_MS = 15_000;

export class OnboardApiError extends Error {
  constructor(
    public status: number,
    message: string,
    public code?: string
  ) {
    super(message);
    this.name = "OnboardApiError";
  }
}

export type OnboardApi = <T = Record<string, any>>(path: string, init?: { method?: string; body?: unknown; token?: string }) => Promise<T>;

export interface ApiOptions {
  baseUrl?: string;
  fetchImpl?: typeof fetch;
  retries?: number;
  baseDelayMs?: number;
  timeoutMs?: number;
}

const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Small JSON client for Daywalker Auth. Retries network errors and 5xx for GET, and 429 for any method.
 * Passwords, session tokens and API tokens travel through it, so the base URL must be https (http only for
 * localhost), redirects are refused and every attempt times out.
 */
export function createApi({
  baseUrl = DEFAULT_AUTH_URL,
  fetchImpl = globalThis.fetch,
  retries = 2,
  baseDelayMs = 400,
  timeoutMs = ONBOARD_API_TIMEOUT_MS,
}: ApiOptions = {}): OnboardApi {
  const base = baseUrl.trim().replace(/\/+$/, "");
  assertSecureUrl("DAYWALKER_AUTH_URL", base);
  return async function api(path, { method = "GET", body, token } = {}) {
    const idempotent = method === "GET";
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await fetchImpl(`${base}${path}`, {
          method,
          headers: {
            Accept: "application/json",
            ...(body ? { "Content-Type": "application/json" } : {}),
            ...(token ? { Authorization: `Bearer ${token}` } : {}),
          },
          body: body ? JSON.stringify(body) : undefined,
          redirect: "error",
          signal: AbortSignal.timeout(timeoutMs),
        });
      } catch (err) {
        if (!idempotent || attempt >= retries) throw new OnboardApiError(0, `Network error: ${(err as Error).message}`);
        await sleep(baseDelayMs * 2 ** attempt);
        continue;
      }
      const retryable = res.status === 429 || (res.status >= 500 && idempotent);
      if (retryable && attempt < retries) {
        const retryAfter = Number(res.headers?.get?.("Retry-After"));
        await sleep(retryAfter > 0 ? Math.min(retryAfter * 1000, 5000) : baseDelayMs * 2 ** attempt);
        continue;
      }
      const data = (await res.json().catch(() => ({}))) as Record<string, any>;
      if (!res.ok) {
        const message = String(data.message || data.error || `HTTP ${res.status}`);
        throw new OnboardApiError(res.status, res.status === 429 ? `Rate limited: ${message}` : message, data.code);
      }
      return data as any;
    }
  };
}
