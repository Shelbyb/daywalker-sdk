import { publicHostname } from "../config.js";
import { OnboardApiError, type OnboardApi } from "./api.js";

export const DEFAULT_LOCAL_ORIGIN = "https://localhost:3000";
export const STAGES = ["new", "signed_up", "verified", "token_created", "registered"] as const;
export type Stage = (typeof STAGES)[number];

export interface OnboardState {
  stage: Stage;
  name?: string;
  email?: string;
  domain?: string;
  service?: string;
}

export interface ServiceInfo {
  id: string;
  slug: string;
  name?: string;
  status?: string;
}

export function stageAtLeast(state: Pick<OnboardState, "stage"> | null | undefined, stage: Stage): boolean {
  return STAGES.indexOf(state?.stage ?? "new") >= STAGES.indexOf(stage);
}

/** Returns the origin of a public https URL (bare hosts get https://), or null if unusable. */
export function normalizeAppUrl(input: unknown): string | null {
  if (typeof input !== "string" || !input.trim()) return null;
  const raw = /^[a-z][a-z0-9+.-]*:\/\//i.test(input.trim()) ? input.trim() : `https://${input.trim()}`;
  try {
    const url = new URL(raw);
    if (url.protocol !== "https:" || !publicHostname(url.hostname)) return null;
    return url.origin;
  } catch {
    return null;
  }
}

/** Local origins first, then the app origin, deduplicated. Local origins must be valid URLs. */
export function buildAllowedOrigins(appOrigin: string, localOrigins: string[] = [DEFAULT_LOCAL_ORIGIN]): string[] {
  const origins = [...localOrigins, appOrigin].map((o) => {
    try {
      return new URL(o).origin;
    } catch {
      throw new Error(`Invalid origin: ${o}`);
    }
  });
  return [...new Set(origins)];
}

/** Mirrors the Daywalker server rule: 12-72 bytes and three of four character classes. */
export function validatePassword(password: unknown): string | null {
  if (typeof password !== "string") return "Password is required";
  if (password.length < 12) return "Password must be at least 12 characters";
  if (Buffer.byteLength(password, "utf8") > 72) return "Password must be at most 72 bytes";
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(password)).length;
  if (classes < 3) return "Password must include three of: lowercase, uppercase, digit, symbol";
  return null;
}

/** Accepts a raw token or the emailed link (`.../verify-email?token=...`). */
export function extractToken(input: string | null | undefined): string | null {
  const value = (input ?? "").trim();
  if (!value) return null;
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(value)) {
    try {
      const url = new URL(value);
      const token = url.searchParams.get("token") || new URLSearchParams(url.hash.replace(/^#/, "")).get("token");
      return token ? token.trim() : null;
    } catch {
      return null;
    }
  }
  if (/[\s?&=]/.test(value)) {
    const token = new URLSearchParams(value.replace(/^.*\?/, "")).get("token");
    return token ? token.trim() : null;
  }
  return value;
}

export const signup = (api: OnboardApi, input: { name: string; email: string; password: string; serviceSlug?: string }) =>
  api("/api/v1/auth/signup", {
    method: "POST",
    body: { name: input.name, email: input.email, password: input.password, ...(input.serviceSlug ? { serviceSlug: input.serviceSlug } : {}) },
  });

export const verifyEmail = (api: OnboardApi, token: string) => api("/api/v1/auth/verify-email", { method: "POST", body: { token } });

/** Returns a session token. MFA accounts cannot use this flow. */
export async function login(api: OnboardApi, input: { email: string; password: string }): Promise<string> {
  const data = await api("/api/v1/auth/login", { method: "POST", body: input });
  if (data.mfaRequired) {
    throw new OnboardApiError(403, "This account has MFA enabled. Create the token in the Daywalker dashboard instead.", "MFA_REQUIRED");
  }
  if (!data.token) throw new OnboardApiError(500, "Login succeeded but returned no session token");
  return String(data.token);
}

export async function listServices(api: OnboardApi, sessionToken: string): Promise<ServiceInfo[]> {
  const data = await api("/api/v1/services", { token: sessionToken });
  // Slugs end up in .env.local and on the terminal: keep only well-formed entries.
  return (Array.isArray(data.services) ? data.services : []).filter(
    (s: ServiceInfo) => s && typeof s.id === "string" && s.id && typeof s.slug === "string" && /^[a-z0-9_-]+$/.test(s.slug)
  );
}

export async function createToken(
  api: OnboardApi,
  sessionToken: string,
  input: { serviceId: string; slug: string; allowedOrigins: string[] }
): Promise<string> {
  const data = await api("/api/v1/tokens", {
    method: "POST",
    token: sessionToken,
    body: {
      name: `${input.slug}-onboard-${new Date().toISOString().slice(0, 10)}`,
      serviceId: input.serviceId,
      expiresAt: new Date(Date.now() + 365 * 24 * 60 * 60 * 1000).toISOString(),
      allowedOrigins: input.allowedOrigins,
    },
  });
  if (!data.rawSecret) throw new OnboardApiError(500, "Token was created but the server returned no secret");
  return String(data.rawSecret);
}
