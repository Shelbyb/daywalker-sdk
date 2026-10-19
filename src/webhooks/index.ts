/**
 * Verify DevPulse webhooks, signed with Standard Webhooks (https://www.standardwebhooks.com):
 * `webhook-signature: v1,<base64 HMAC-SHA256(key, "${webhook-id}.${webhook-timestamp}.${raw body}")>`
 * where the key is the base64 part of the endpoint's `whsec_…` secret. WebCrypto only, so it runs
 * in Node, Deno, Bun, Cloudflare Workers and edge runtimes.
 *
 * Always verify the raw request body (before any JSON parsing), and de-duplicate on `webhook-id`:
 * DevPulse retries failed deliveries with the same id.
 */

/** Event types DevPulse emits (subscriptions accept `*` wildcards such as `flag.*`). */
export type WebhookEventType =
  | "ping"
  | `flag.${string}`
  | "segment.updated"
  | `experiment.${string}`
  | `incident.${string}`
  | `maintenance.${string}`
  | `status_page.${string}`
  | `error.${string}`
  | `secret.${string}`
  | `cron.${string}`
  | `slo.${string}`
  | `changelog.${string}`
  | (string & {});

/** The JSON body of every DevPulse webhook. */
export type WebhookEvent<D = Record<string, unknown>> = {
  type: WebhookEventType;
  /** ISO 8601 time the event happened. */
  timestamp: string;
  data: D;
};

export type VerifyOptions = {
  /** The endpoint's signing secret (`whsec_…`). Pass an array while rotating secrets. */
  secret: string | string[];
  /** Request headers (a Headers object, or a plain object such as Express/Node `req.headers`). */
  headers: Headers | Record<string, string | string[] | undefined>;
  /** The raw request body, exactly as received. */
  body: string | Uint8Array | ArrayBuffer;
  /** Allowed clock skew in seconds, both ways. Default 300 (5 minutes). */
  toleranceSeconds?: number;
  /** Test seam: current time in ms. */
  now?: number;
};

export type WebhookErrorCode = "MISSING_HEADERS" | "INVALID_TIMESTAMP" | "TIMESTAMP_OUT_OF_TOLERANCE" | "INVALID_SECRET" | "INVALID_SIGNATURE" | "INVALID_PAYLOAD";

export class WebhookVerificationError extends Error {
  readonly code: WebhookErrorCode;
  constructor(code: WebhookErrorCode, message: string) {
    super(message);
    this.name = "WebhookVerificationError";
    this.code = code;
  }
}

const enc = new TextEncoder();

function header(h: VerifyOptions["headers"], name: string): string | undefined {
  if (typeof (h as Headers).get === "function") return (h as Headers).get(name) ?? undefined;
  const rec = h as Record<string, string | string[] | undefined>;
  const key = Object.keys(rec).find((k) => k.toLowerCase() === name);
  const v = key === undefined ? undefined : rec[key];
  return Array.isArray(v) ? v.join(" ") : v;
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function b64encode(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s);
}

function secretBytes(secret: string): Uint8Array {
  const raw = secret.startsWith("whsec_") ? secret.slice(6) : secret;
  let key: Uint8Array;
  try {
    key = b64decode(raw);
  } catch {
    throw new WebhookVerificationError("INVALID_SECRET", "Webhook secret must be whsec_ followed by base64");
  }
  if (key.length < 16) throw new WebhookVerificationError("INVALID_SECRET", "Webhook secret is too short");
  return key;
}

function bodyBytes(body: VerifyOptions["body"]): Uint8Array {
  if (typeof body === "string") return enc.encode(body);
  return body instanceof Uint8Array ? body : new Uint8Array(body);
}

async function hmac(key: Uint8Array, parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const msg = new Uint8Array(total);
  let o = 0;
  for (const p of parts) {
    msg.set(p, o);
    o += p.length;
  }
  const k = await crypto.subtle.importKey("raw", key as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", k, msg as BufferSource));
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
  return diff === 0;
}

/** Compute the `v1,<base64>` signature for a message (useful for tests and local replays). */
export async function signWebhook(secret: string, id: string, timestamp: number, body: string | Uint8Array): Promise<string> {
  const mac = await hmac(secretBytes(secret), [enc.encode(`${id}.${timestamp}.`), bodyBytes(body)]);
  return `v1,${b64encode(mac)}`;
}

/**
 * Verify a delivery and return its parsed event. Throws `WebhookVerificationError` (answer 400 or
 * 401) when headers are missing, the timestamp is outside the tolerance, or no signature matches.
 * The header may carry several space-separated signatures; any one matching any secret is enough.
 */
export async function verifyWebhook<D = Record<string, unknown>>(options: VerifyOptions): Promise<WebhookEvent<D>> {
  const id = header(options.headers, "webhook-id");
  const ts = header(options.headers, "webhook-timestamp");
  const sig = header(options.headers, "webhook-signature");
  if (!id || !ts || !sig) throw new WebhookVerificationError("MISSING_HEADERS", "Missing webhook-id, webhook-timestamp or webhook-signature header");
  if (!/^\d{1,12}$/.test(ts.trim())) throw new WebhookVerificationError("INVALID_TIMESTAMP", "webhook-timestamp must be Unix seconds");
  const seconds = Number(ts.trim());
  const tolerance = options.toleranceSeconds ?? 300;
  const now = Math.floor((options.now ?? Date.now()) / 1000);
  if (Math.abs(now - seconds) > tolerance) throw new WebhookVerificationError("TIMESTAMP_OUT_OF_TOLERANCE", "Webhook timestamp is too old or too far in the future");

  const body = bodyBytes(options.body);
  const prefix = enc.encode(`${id}.${seconds}.`);
  const candidates: Uint8Array[] = [];
  for (const part of sig.split(" ")) {
    const [version, value] = part.split(",", 2);
    if (version !== "v1" || !value) continue;
    try {
      candidates.push(b64decode(value));
    } catch {
      /* skip malformed entries */
    }
  }
  const secrets = Array.isArray(options.secret) ? options.secret : [options.secret];
  if (!secrets.length) throw new WebhookVerificationError("INVALID_SECRET", "No webhook secret configured");
  let ok = false;
  for (const s of secrets) {
    const expected = await hmac(secretBytes(s), [prefix, body]);
    // Check every candidate so timing does not reveal which one matched.
    for (const c of candidates) ok = constantTimeEqual(expected, c) || ok;
  }
  if (!ok) throw new WebhookVerificationError("INVALID_SIGNATURE", "No matching webhook signature");

  let event: unknown;
  try {
    event = JSON.parse(new TextDecoder().decode(body));
  } catch {
    throw new WebhookVerificationError("INVALID_PAYLOAD", "Webhook body is not JSON");
  }
  if (!event || typeof event !== "object" || typeof (event as WebhookEvent).type !== "string") throw new WebhookVerificationError("INVALID_PAYLOAD", "Webhook body is not a DevPulse event");
  return event as WebhookEvent<D>;
}

/** Narrow an event by type: `if (isEventType(event, "flag.updated")) …`. Supports a trailing `*`. */
export function isEventType<T extends string>(event: WebhookEvent, type: T): boolean {
  return type.endsWith("*") ? event.type.startsWith(type.slice(0, -1)) : event.type === type;
}
