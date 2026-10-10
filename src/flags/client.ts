import type { ContextInput, EvaluationReason, FlagValue } from "./engine/index.js";
import { EventProcessor, SseClient, encodeContext, noopLogger, type Logger } from "./common/index.js";

export type { ContextInput, EvaluationReason, FlagValue, Logger };

export interface FlagState {
  value: FlagValue;
  variation: number | null;
  version: number;
  reason?: EvaluationReason;
  trackEvents?: boolean;
  trackReason?: boolean;
}

export type FlagSet = Record<string, FlagState>;

export interface ClientOptions {
  /** Base URL of your DevPulse deployment, e.g. https://flags.example.com */
  baseUrl: string;
  /** Receive changes in real time over Server-Sent Events (default true). */
  streaming?: boolean;
  /** Initial flag values, e.g. from the Node SDK's allFlagsState() for SSR. */
  bootstrap?: FlagSet | Record<string, FlagValue>;
  /** Secure mode hash for the context (HMAC-SHA256 computed on your server). */
  hash?: string;
  /** Include evaluation reasons (for variationDetail). */
  withReasons?: boolean;
  sendEvents?: boolean;
  flushIntervalMs?: number;
  privateAttributes?: string[];
  allAttributesPrivate?: boolean;
  /** Cache the last flags in localStorage and use them while loading. */
  cache?: boolean;
  fetch?: typeof fetch;
  logger?: Logger;
}

export interface EvaluationDetail<T = FlagValue> {
  value: T;
  variationIndex: number | null;
  reason: EvaluationReason | null;
}

type ChangeSet = Record<string, { current: FlagValue; previous: FlagValue | undefined }>;
type Listener = (...args: unknown[]) => void;

function isFlagSet(x: unknown): x is FlagSet {
  return !!x && typeof x === "object" && Object.values(x).every((v) => v && typeof v === "object" && "value" in (v as object) && "version" in (v as object));
}

/**
 * A client for one evaluation context. Fetches evaluated flags, keeps them
 * current over SSE, and reports analytics.
 *
 *   const client = createClient("<client-side id>", { key: user.id }, { baseUrl });
 *   await client.waitForInitialization();
 *   client.on("change:new-checkout", (value) => render(value));
 *   client.variation("new-checkout", false);
 */
export class DevPulseClient {
  private flags: FlagSet = {};
  private listeners = new Map<string, Set<Listener>>();
  private stream: SseClient | null = null;
  private events: EventProcessor | null = null;
  private ready: Promise<void>;
  private resolveReady!: () => void;
  private rejectReady!: (e: Error) => void;
  private initialized = false;
  private closed = false;
  private readonly logger: Logger;
  private readonly base: string;

  constructor(
    private readonly clientSideId: string,
    private context: ContextInput,
    private readonly options: ClientOptions,
  ) {
    this.logger = options.logger ?? noopLogger;
    this.base = options.baseUrl.replace(/\/$/, "");
    this.ready = new Promise((res, rej) => {
      this.resolveReady = res;
      this.rejectReady = rej;
    });
    this.ready.catch(() => undefined);

    if (options.bootstrap) {
      this.flags = isFlagSet(options.bootstrap)
        ? { ...options.bootstrap }
        : Object.fromEntries(Object.entries(options.bootstrap).map(([k, v]) => [k, { value: v as FlagValue, variation: null, version: 0 }]));
      this.markReady();
    } else if (options.cache) {
      const cached = this.readCache();
      if (cached) this.flags = cached;
    }

    if (options.sendEvents !== false && typeof globalThis.fetch === "function") {
      this.events = new EventProcessor({
        url: `${this.base}/sdk/v1/events/client/${encodeURIComponent(clientSideId)}`,
        flushIntervalMs: options.flushIntervalMs ?? 5000,
        privateAttributes: options.privateAttributes,
        allAttributesPrivate: options.allAttributesPrivate,
        fetch: options.fetch,
        beacon: true,
        logger: this.logger,
      });
      this.events.identify(context);
      const doc = (globalThis as { document?: { addEventListener: (t: string, f: () => void) => void; visibilityState?: string } }).document;
      doc?.addEventListener("visibilitychange", () => {
        if (doc.visibilityState === "hidden") void this.events?.flush();
      });
    }

    void this.start();
  }

  private query() {
    const p = new URLSearchParams({ context: encodeContext(this.context) });
    if (this.options.hash) p.set("h", this.options.hash);
    if (this.options.withReasons) p.set("withReasons", "true");
    return p.toString();
  }

  private async start() {
    if (this.options.streaming === false) {
      try {
        this.replaceAll(await this.fetchFlags());
      } catch (err) {
        this.fail(err as Error);
      }
      return;
    }
    this.stream = new SseClient({
      url: () => `${this.base}/sdk/v1/client/${encodeURIComponent(this.clientSideId)}/stream?${this.query()}`,
      fetch: this.options.fetch,
      onEvent: (ev) => this.onStreamEvent(ev.type, ev.data),
      onOpen: () => this.logger.debug("DevPulse stream connected"),
      onError: (err) => {
        this.logger.warn(`DevPulse stream error: ${err.message}`);
        if (!err.recoverable) {
          this.fail(err);
          return false;
        }
        // Keep serving flags while reconnecting; fetch once so a first load still succeeds.
        if (!this.initialized) this.fetchFlags().then((f) => this.replaceAll(f), () => undefined);
        return true;
      },
    });
    this.stream.start();
  }

  private async fetchFlags(): Promise<FlagSet> {
    const res = await (this.options.fetch ?? fetch)(`${this.base}/sdk/v1/client/${encodeURIComponent(this.clientSideId)}/flags?${this.query()}`);
    if (!res.ok) throw new Error(`Flag request failed with ${res.status}`);
    return (await res.json()) as FlagSet;
  }

  private onStreamEvent(type: string, data: string) {
    try {
      const payload = JSON.parse(data);
      if (type === "put") this.replaceAll(payload as FlagSet);
      else if (type === "patch") {
        const { key, ...state } = payload as FlagState & { key: string };
        const prev = this.flags[key];
        if (prev && prev.version > state.version) return;
        this.flags[key] = state;
        this.emitChanges({ [key]: { current: state.value, previous: prev?.value } });
        this.writeCache();
      } else if (type === "delete") {
        const { key, version } = payload as { key: string; version: number };
        const prev = this.flags[key];
        if (!prev || prev.version > version) return;
        delete this.flags[key];
        this.emitChanges({ [key]: { current: null, previous: prev.value } });
        this.writeCache();
      }
    } catch (err) {
      this.logger.error("Malformed stream event", err);
    }
  }

  private replaceAll(next: FlagSet) {
    const changes: ChangeSet = {};
    for (const key of new Set([...Object.keys(this.flags), ...Object.keys(next)])) {
      const a = this.flags[key]?.value;
      const b = next[key]?.value;
      if (JSON.stringify(a) !== JSON.stringify(b)) changes[key] = { current: b ?? null, previous: a };
    }
    this.flags = { ...next };
    this.writeCache();
    this.markReady();
    if (Object.keys(changes).length) this.emitChanges(changes);
  }

  private markReady() {
    if (this.initialized) return;
    this.initialized = true;
    this.resolveReady();
    this.emit("ready");
  }

  private fail(err: Error) {
    if (!this.initialized) this.rejectReady(err);
    this.emit("failed", err);
  }

  private emitChanges(changes: ChangeSet) {
    this.emit("change", changes);
    for (const [key, c] of Object.entries(changes)) this.emit(`change:${key}`, c.current, c.previous);
  }

  private cacheKey() {
    return `devpulse:${this.clientSideId}:${encodeContext(this.context)}`;
  }
  private readCache(): FlagSet | null {
    try {
      const raw = (globalThis as { localStorage?: Storage }).localStorage?.getItem(this.cacheKey());
      return raw ? (JSON.parse(raw) as FlagSet) : null;
    } catch {
      return null;
    }
  }
  private writeCache() {
    if (!this.options.cache) return;
    try {
      (globalThis as { localStorage?: Storage }).localStorage?.setItem(this.cacheKey(), JSON.stringify(this.flags));
    } catch {
      /* storage full or unavailable */
    }
  }

  // ---------- Public API ----------

  /** Resolves once flags are loaded (or rejects on a fatal error such as an invalid client-side ID). */
  waitForInitialization(opts: { timeoutMs?: number } = {}): Promise<void> {
    if (!opts.timeoutMs) return this.ready;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<void>((_, rej) => {
      timer = setTimeout(() => rej(new Error("DevPulse initialization timed out")), opts.timeoutMs);
    });
    return Promise.race([this.ready, timeout]).finally(() => clearTimeout(timer));
  }

  get isInitialized() {
    return this.initialized;
  }

  variation<T extends FlagValue>(key: string, defaultValue: T): T {
    return this.variationDetail(key, defaultValue).value;
  }

  variationDetail<T extends FlagValue>(key: string, defaultValue: T): EvaluationDetail<T> {
    const f = this.flags[key];
    let detail: EvaluationDetail<T>;
    if (!f) detail = { value: defaultValue, variationIndex: null, reason: { kind: "ERROR", errorKind: this.initialized ? "FLAG_NOT_FOUND" : "CLIENT_NOT_READY" } };
    // A null value means "off with no off variation": serve the caller's default.
    else if (f.value === null) detail = { value: defaultValue, variationIndex: f.variation, reason: f.reason ?? null };
    else if (defaultValue !== null && typeof defaultValue !== typeof f.value) detail = { value: defaultValue, variationIndex: null, reason: { kind: "ERROR", errorKind: "WRONG_TYPE" } };
    else detail = { value: f.value as T, variationIndex: f.variation, reason: f.reason ?? null };
    this.events?.recordEvaluation({ key, context: this.context, value: detail.value, default: defaultValue, variation: detail.variationIndex, version: f?.version, reason: f?.reason, trackEvents: f?.trackEvents });
    return detail;
  }

  boolVariation(key: string, defaultValue: boolean) {
    return this.variation(key, defaultValue);
  }
  stringVariation(key: string, defaultValue: string) {
    return this.variation(key, defaultValue);
  }
  numberVariation(key: string, defaultValue: number) {
    return this.variation(key, defaultValue);
  }
  jsonVariation<T extends FlagValue>(key: string, defaultValue: T) {
    return this.variation(key, defaultValue);
  }

  /** All flag values (doesn't record evaluations). */
  allFlags(): Record<string, FlagValue> {
    return Object.fromEntries(Object.entries(this.flags).map(([k, v]) => [k, v.value]));
  }

  /** Switch to a different context (e.g. after login). Resolves with the new flags. */
  async identify(context: ContextInput, opts: { hash?: string } = {}): Promise<Record<string, FlagValue>> {
    this.context = context;
    if (opts.hash !== undefined) this.options.hash = opts.hash;
    this.events?.identify(context);
    this.replaceAll(await this.fetchFlags());
    this.stream?.restart();
    return this.allFlags();
  }

  getContext(): ContextInput {
    return this.context;
  }

  /** Record a custom event for metrics and experiments. */
  track(key: string, data?: unknown, metricValue?: number) {
    this.events?.track(key, this.context, data, metricValue);
  }

  on(event: "ready" | "failed" | "change" | `change:${string}`, fn: Listener) {
    let set = this.listeners.get(event);
    if (!set) this.listeners.set(event, (set = new Set()));
    set.add(fn);
    return () => this.off(event, fn);
  }

  off(event: string, fn: Listener) {
    this.listeners.get(event)?.delete(fn);
  }

  private emit(event: string, ...args: unknown[]) {
    for (const fn of this.listeners.get(event) ?? []) {
      try {
        fn(...args);
      } catch (err) {
        this.logger.error(`Listener for "${event}" threw`, err);
      }
    }
  }

  async flush() {
    await this.events?.flush();
  }

  async close() {
    if (this.closed) return;
    this.closed = true;
    this.stream?.stop();
    await this.events?.close();
    this.listeners.clear();
  }
}

export function createClient(clientSideId: string, context: ContextInput, options: ClientOptions): DevPulseClient {
  return new DevPulseClient(clientSideId, context, options);
}
