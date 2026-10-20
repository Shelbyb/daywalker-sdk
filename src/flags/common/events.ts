import { parseContext, type ContextInput, type EvaluationReason, type FlagValue } from "../engine/index.js";

export interface EventProcessorOptions {
  url: string;
  headers?: Record<string, string>;
  fetch?: typeof fetch;
  flushIntervalMs?: number;
  capacity?: number;
  /** Treat every attribute (except key/kind) as private. */
  allAttributesPrivate?: boolean;
  /** Attribute names (or RFC 6901 pointers) never sent to DevPulse. */
  privateAttributes?: string[];
  /** Use navigator.sendBeacon when available (browsers, on page hide). */
  beacon?: boolean;
  logger?: Logger;
}

export interface Logger {
  debug(...args: unknown[]): void;
  info(...args: unknown[]): void;
  warn(...args: unknown[]): void;
  error(...args: unknown[]): void;
}

export const noopLogger: Logger = { debug() {}, info() {}, warn() {}, error() {} };

/** Delete the value at `tokens` inside `target`, copying (not mutating) nested objects. */
function removePointer(target: Record<string, unknown>, tokens: string[]): boolean {
  const [head, ...rest] = tokens as [string, ...string[]];
  if (!Object.hasOwn(target, head)) return false;
  if (!rest.length) {
    delete target[head];
    return true;
  }
  const child = target[head];
  if (!child || typeof child !== "object" || Array.isArray(child)) return false;
  const copy = { ...(child as Record<string, unknown>) };
  if (!removePointer(copy, rest)) return false;
  target[head] = copy;
  return true;
}

type Counter = { variation?: number; version?: number; value: FlagValue; count: number; unknown?: boolean };

/**
 * Buffers analytics: per-flag summaries (counts per variation), context
 * index events (deduplicated), full feature events for tracked flags and
 * experiments, and custom events. Flushes on an interval and on demand.
 */
export class EventProcessor {
  private summary = new Map<string, { default: FlagValue; counters: Map<string, Counter> }>();
  private summaryStart = 0;
  private queue: Record<string, unknown>[] = [];
  private seenContexts = new Map<string, number>();
  private timer: ReturnType<typeof setInterval> | null = null;
  private disabled = false;
  private readonly logger: Logger;

  constructor(private readonly opts: EventProcessorOptions) {
    this.logger = opts.logger ?? noopLogger;
    this.timer = setInterval(() => void this.flush(), opts.flushIntervalMs ?? 5000);
    (this.timer as { unref?: () => void }).unref?.();
  }

  /** Strip private attributes and record which were removed. */
  redact(context: ContextInput): Record<string, unknown> {
    const strip = (c: Record<string, unknown>) => {
      const meta = (c._meta ?? {}) as { privateAttributes?: string[] };
      const priv = new Set([...(this.opts.privateAttributes ?? []), ...(meta.privateAttributes ?? [])]);
      const out: Record<string, unknown> = {};
      const redacted: string[] = [];
      for (const [k, v] of Object.entries(c)) {
        if (k === "_meta") continue;
        if (k !== "key" && k !== "kind" && k !== "anonymous" && (this.opts.allAttributesPrivate || priv.has(k) || priv.has(`/${k}`))) redacted.push(k);
        else out[k] = v;
      }
      // Nested JSON pointers (/address/zip): remove the leaf from a copy of each object on the path.
      for (const ref of priv) {
        const tokens = ref.startsWith("/") ? ref.slice(1).split("/").map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~")) : [];
        if (tokens.length < 2 || ["key", "kind", "anonymous", "_meta"].includes(tokens[0]!)) continue;
        if (removePointer(out, tokens)) redacted.push(ref);
      }
      if (redacted.length) out.redactedAttributes = redacted;
      return out;
    };
    if (context.kind === "multi") {
      const out: Record<string, unknown> = { kind: "multi" };
      for (const [k, v] of Object.entries(context)) if (k !== "kind") out[k] = strip(v as Record<string, unknown>);
      return out;
    }
    return strip(context);
  }

  private contextKeys(context: ContextInput): Record<string, string> | null {
    try {
      const ctx = parseContext(context);
      return Object.fromEntries([...ctx.kinds.values()].map((c) => [c.kind, c.key]));
    } catch {
      return null;
    }
  }

  /** Queue an index event the first time a context is seen in a while. */
  private noticeContext(context: ContextInput) {
    let canonical: string;
    try {
      canonical = parseContext(context).canonicalKey;
    } catch {
      return;
    }
    const now = Date.now();
    const last = this.seenContexts.get(canonical);
    if (last && now - last < 5 * 60_000) return;
    if (this.seenContexts.size > 1000) this.seenContexts.clear();
    this.seenContexts.set(canonical, now);
    this.push({ kind: "index", creationDate: now, context: this.redact(context) });
  }

  recordEvaluation(e: { key: string; context: ContextInput; value: FlagValue; default: FlagValue; variation: number | null; version?: number; reason?: EvaluationReason; trackEvents?: boolean }) {
    if (this.disabled) return;
    this.noticeContext(e.context);
    if (!this.summaryStart) this.summaryStart = Date.now();
    let s = this.summary.get(e.key);
    if (!s) this.summary.set(e.key, (s = { default: e.default, counters: new Map() }));
    const unknown = e.version === undefined;
    const ck = `${e.variation ?? "default"}:${e.version ?? "unknown"}`;
    const c = s.counters.get(ck) ?? { value: e.value, count: 0, ...(unknown ? { unknown: true } : { variation: e.variation ?? undefined, version: e.version }) };
    c.count++;
    s.counters.set(ck, c);
    const inExperiment = !!e.reason && "inExperiment" in e.reason && e.reason.inExperiment;
    if (e.trackEvents || inExperiment) {
      this.push({ kind: "feature", creationDate: Date.now(), key: e.key, version: e.version, variation: e.variation, value: e.value, default: e.default, contextKeys: this.contextKeys(e.context), ...(e.reason ? { reason: e.reason } : {}) });
    }
  }

  track(key: string, context: ContextInput, data?: unknown, metricValue?: number) {
    if (this.disabled) return;
    this.noticeContext(context);
    const keys = this.contextKeys(context);
    if (!keys) return this.logger.warn("track() called with an invalid context");
    this.push({ kind: "custom", key, creationDate: Date.now(), contextKeys: keys, ...(data !== undefined ? { data } : {}), ...(typeof metricValue === "number" ? { metricValue } : {}) });
  }

  identify(context: ContextInput) {
    if (this.disabled) return;
    try {
      parseContext(context);
    } catch {
      return;
    }
    this.push({ kind: "identify", creationDate: Date.now(), context: this.redact(context) });
  }

  private push(e: Record<string, unknown>) {
    if (this.queue.length >= (this.opts.capacity ?? 10_000)) return this.logger.warn("Event buffer full; dropping events");
    this.queue.push(e);
  }

  private drain(): Record<string, unknown>[] {
    const events = this.queue;
    this.queue = [];
    if (this.summary.size) {
      events.push({
        kind: "summary",
        startDate: this.summaryStart,
        endDate: Date.now(),
        features: Object.fromEntries([...this.summary.entries()].map(([k, s]) => [k, { default: s.default, counters: [...s.counters.values()] }])),
      });
      this.summary.clear();
      this.summaryStart = 0;
    }
    return events;
  }

  async flush(): Promise<void> {
    if (this.disabled) return;
    const events = this.drain();
    if (!events.length) return;
    for (const body of chunkEvents(events, this.logger)) {
      if (this.disabled) return;
      await this.send(body);
    }
  }

  private async send(body: string) {
    const bytes = byteLength(body);
    const g = globalThis as { navigator?: { sendBeacon?: (u: string, d: string) => boolean }; document?: { visibilityState?: string } };
    // Beacons and keepalive requests share a 64 KiB in-flight budget in browsers; bigger bodies fail outright.
    if (this.opts.beacon && g.navigator?.sendBeacon && g.document?.visibilityState === "hidden" && bytes < KEEPALIVE_MAX_BYTES) {
      if (g.navigator.sendBeacon(this.opts.url, body)) return;
    }
    for (let attempt = 0; attempt < 2; attempt++) {
      const timeout = requestTimeout();
      try {
        const res = await (this.opts.fetch ?? fetch)(this.opts.url, {
          method: "POST",
          headers: { "content-type": "application/json", ...this.opts.headers },
          body,
          keepalive: bytes < KEEPALIVE_MAX_BYTES,
          signal: timeout.signal,
        });
        if (res.ok) return;
        if (res.status === 401 || res.status === 403) {
          this.disabled = true;
          return this.logger.error(`Events rejected (${res.status}); analytics disabled. Check your SDK key.`);
        }
        if (res.status < 500 && res.status !== 429) return this.logger.warn(`Events rejected (${res.status})`);
      } catch (err) {
        if (attempt === 1) this.logger.warn("Failed to send events", err);
      } finally {
        timeout.clear();
      }
      if (attempt === 0) await new Promise((r) => unrefTimer(setTimeout(r, 1000)));
    }
  }

  async close() {
    if (this.timer) clearInterval(this.timer);
    await this.flush();
  }
}

/** DevPulse accepts at most this many events per POST (the rest are silently dropped). */
export const MAX_EVENTS_PER_REQUEST = 5000;
/** Browser event bodies are capped at 512 KB by DevPulse; stay under it with room for brackets. */
export const MAX_REQUEST_BYTES = 500_000;
/** keepalive / sendBeacon bodies must fit in the browser's 64 KiB in-flight budget. */
export const KEEPALIVE_MAX_BYTES = 60_000;

const encoder = new TextEncoder();
const byteLength = (s: string) => encoder.encode(s).length;

function unrefTimer(t: ReturnType<typeof setTimeout>) {
  (t as { unref?: () => void }).unref?.();
  return t;
}

/** Default timeout for SDK HTTP requests (flags, polling, events), so a stalled server can't hang them. */
export const REQUEST_TIMEOUT_MS = 30_000;

/** An abort signal that fires after `ms` (AbortController + timer: AbortSignal.timeout isn't available everywhere). */
export function requestTimeout(ms = REQUEST_TIMEOUT_MS): { signal: AbortSignal; clear: () => void } {
  const controller = new AbortController();
  const timer = unrefTimer(setTimeout(() => controller.abort(), ms));
  return { signal: controller.signal, clear: () => clearTimeout(timer) };
}

/** Split events into JSON array bodies of at most MAX_EVENTS_PER_REQUEST events and MAX_REQUEST_BYTES bytes. */
export function chunkEvents(events: Record<string, unknown>[], logger: Logger = noopLogger, maxBytes = MAX_REQUEST_BYTES, maxEvents = MAX_EVENTS_PER_REQUEST): string[] {
  const bodies: string[] = [];
  let parts: string[] = [];
  let size = 2; // "[" + "]"
  for (const e of events) {
    const json = JSON.stringify(e);
    const n = byteLength(json);
    if (n + 2 > maxBytes) {
      logger.warn(`Dropping a ${String(e.kind)} event of ${n} bytes (over the ${maxBytes}-byte request limit)`);
      continue;
    }
    if (parts.length && (parts.length >= maxEvents || size + n + 1 > maxBytes)) {
      bodies.push(`[${parts.join(",")}]`);
      parts = [];
      size = 2;
    }
    size += n + (parts.length ? 1 : 0);
    parts.push(json);
  }
  if (parts.length) bodies.push(`[${parts.join(",")}]`);
  return bodies;
}
