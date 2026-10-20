import type { ContextInput, EvaluationReason, FlagValue } from "./engine/index.js";
import { EventProcessor, SDK_VERSION, SseClient, encodeContext, noopLogger, requestTimeout, type Logger } from "./common/index.js";
import { assertSecureUrl } from "../secure-url.js";

export type { ContextInput, EvaluationReason, FlagValue, Logger };
export { SDK_VERSION };

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
  /** Base URL of your DevPulse deployment, e.g. https://flags.example.com (https required except on localhost). */
  baseUrl: string;
  /** Receive changes in real time over Server-Sent Events (default true). */
  streaming?: boolean;
  /**
   * Never touch the network: serve `bootstrap` (or defaults), send no events, open no stream.
   * identify() only switches the context. Used for server-side rendering; handy in tests.
   * The client is ready immediately when `bootstrap` is given.
   */
  offline?: boolean;
  /** Initial flag values, e.g. from the Node SDK's allFlagsState().toJSON() for SSR. */
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

/** A flag map without a prototype, so keys like `__proto__` or `toString` never resolve to inherited values. */
function flagMap(entries: Record<string, FlagState> = {}): FlagSet {
  return Object.assign(Object.create(null) as FlagSet, entries);
}

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
  private flags: FlagSet = flagMap();
  /** Versions of flags deleted since the last full load, so an older patch can't resurrect them. */
  private deleted = new Map<string, number>();
  private listeners = new Map<string, Set<Listener>>();
  private stream: SseClient | null = null;
  private events: EventProcessor | null = null;
  private ready: Promise<void>;
  private resolveReady!: () => void;
  private rejectReady!: (e: Error) => void;
  private initialized = false;
  private closed = false;
  /** Bumped by identify(); responses for an older context are ignored. */
  private contextSeq = 0;
  private stale = false;
  private detachVisibility: (() => void) | null = null;
  private readonly logger: Logger;
  private readonly base: string;

  constructor(
    private readonly clientSideId: string,
    private context: ContextInput,
    private readonly options: ClientOptions,
  ) {
    this.logger = options.logger ?? noopLogger;
    assertSecureUrl("baseUrl", options.baseUrl);
    this.base = options.baseUrl.replace(/\/$/, "");
    this.ready = new Promise((res, rej) => {
      this.resolveReady = res;
      this.rejectReady = rej;
    });
    this.ready.catch(() => undefined);

    if (options.bootstrap) {
      this.flags = isFlagSet(options.bootstrap)
        ? flagMap(options.bootstrap)
        : flagMap(Object.fromEntries(Object.entries(options.bootstrap).map(([k, v]) => [k, { value: v as FlagValue, variation: null, version: 0 }])));
      this.markReady();
    } else if (options.cache) {
      const cached = this.readCache();
      if (cached) this.flags = flagMap(cached);
    }

    if (options.offline) return;

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
      type Doc = { addEventListener: (t: string, f: () => void) => void; removeEventListener: (t: string, f: () => void) => void; visibilityState?: string };
      const doc = (globalThis as { document?: Doc }).document;
      if (doc?.addEventListener) {
        const onVisibility = () => {
          if (doc.visibilityState === "hidden") void this.events?.flush();
        };
        doc.addEventListener("visibilitychange", onVisibility);
        this.detachVisibility = () => doc.removeEventListener("visibilitychange", onVisibility);
      }
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
        await this.loadFlags();
      } catch (err) {
        if (!this.closed) this.fail(err as Error);
      }
      return;
    }
    this.stream = new SseClient({
      url: () => `${this.base}/sdk/v1/client/${encodeURIComponent(this.clientSideId)}/stream?${this.query()}`,
      fetch: this.options.fetch,
      onEvent: (ev) => this.onStreamEvent(ev.type, ev.data),
      onOpen: () => {
        this.logger.debug("DevPulse stream connected");
        this.setStale(false);
      },
      onError: (err) => {
        this.logger.warn(`DevPulse stream error: ${err.message}`);
        if (!err.recoverable) {
          this.fail(err);
          return false;
        }
        // Keep serving flags while reconnecting; fetch once so a first load still succeeds.
        this.setStale(true, err);
        if (!this.initialized) this.loadFlags().catch(() => undefined);
        return true;
      },
    });
    this.stream.start();
  }

  /** Fetch flags for the current context and apply them unless identify() moved on (or close()) meanwhile. */
  private async loadFlags(): Promise<boolean> {
    const seq = this.contextSeq;
    const flags = await this.fetchFlags();
    if (seq !== this.contextSeq || this.closed) return false;
    this.replaceAll(flags);
    return true;
  }

  private async fetchFlags(): Promise<FlagSet> {
    const timeout = requestTimeout();
    try {
      const res = await (this.options.fetch ?? fetch)(`${this.base}/sdk/v1/client/${encodeURIComponent(this.clientSideId)}/flags?${this.query()}`, { signal: timeout.signal });
      if (!res.ok) throw new Error(`Flag request failed with ${res.status}`);
      return (await res.json()) as FlagSet;
    } finally {
      timeout.clear();
    }
  }

  private onStreamEvent(type: string, data: string) {
    try {
      const payload = JSON.parse(data);
      if (type === "put") this.replaceAll(payload as FlagSet);
      else if (type === "patch") {
        const { key, ...state } = payload as FlagState & { key: string };
        if (typeof key !== "string" || typeof state.version !== "number") throw new Error("patch without key or version");
        const prev = this.flag(key);
        if (prev && prev.version > state.version) return;
        if ((this.deleted.get(key) ?? -Infinity) >= state.version) return;
        this.deleted.delete(key);
        this.flags[key] = state;
        this.emitChanges({ [key]: { current: state.value, previous: prev?.value } });
        this.writeCache();
      } else if (type === "delete") {
        const { key, version } = payload as { key: string; version: number };
        if (typeof key !== "string" || typeof version !== "number") throw new Error("delete without key or version");
        const prev = this.flag(key);
        if (prev ? prev.version > version : (this.deleted.get(key) ?? -Infinity) >= version) return;
        this.deleted.set(key, version);
        if (!prev) return;
        delete this.flags[key];
        this.emitChanges({ [key]: { current: null, previous: prev.value } });
        this.writeCache();
      }
    } catch (err) {
      this.logger.error("Malformed stream event", err);
    }
  }

  private replaceAll(next: FlagSet) {
    const changes: ChangeSet = Object.create(null) as ChangeSet;
    for (const key of new Set([...Object.keys(this.flags), ...Object.keys(next)])) {
      const a = this.flag(key)?.value;
      const b = Object.hasOwn(next, key) ? next[key]?.value : undefined;
      if (JSON.stringify(a) !== JSON.stringify(b)) changes[key] = { current: b ?? null, previous: a };
    }
    this.flags = flagMap(next);
    this.deleted.clear();
    this.writeCache();
    this.markReady();
    if (Object.keys(changes).length) this.emitChanges(changes);
  }

  private flag(key: string): FlagState | undefined {
    return Object.hasOwn(this.flags, key) ? this.flags[key] : undefined;
  }

  private markReady() {
    if (this.initialized) return;
    this.initialized = true;
    this.resolveReady();
    this.emit("ready");
  }

  /** "stale" when the stream drops after loading (flags keep serving), "recovered" once it reconnects. */
  private setStale(stale: boolean, err?: Error) {
    if (!this.initialized || this.closed || this.stale === stale) return;
    this.stale = stale;
    if (stale) this.emit("stale", err);
    else this.emit("recovered");
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

  /** True after close(); a closed client never updates again. */
  get isClosed() {
    return this.closed;
  }

  variation<T extends FlagValue>(key: string, defaultValue: T): T {
    return this.variationDetail(key, defaultValue).value;
  }

  variationDetail<T extends FlagValue>(key: string, defaultValue: T): EvaluationDetail<T> {
    const detail = this.peekVariationDetail(key, defaultValue);
    this.recordEvaluation(key, defaultValue, detail);
    return detail;
  }

  /** @internal Evaluate without recording an analytics event (React hooks record from an effect). */
  peekVariationDetail<T extends FlagValue>(key: string, defaultValue: T): EvaluationDetail<T> {
    const f = this.flag(key);
    let detail: EvaluationDetail<T>;
    if (!f) detail = { value: defaultValue, variationIndex: null, reason: { kind: "ERROR", errorKind: this.initialized ? "FLAG_NOT_FOUND" : "CLIENT_NOT_READY" } };
    // A null value means "off with no off variation": serve the caller's default.
    else if (f.value === null) detail = { value: defaultValue, variationIndex: f.variation, reason: f.reason ?? null };
    else if (defaultValue !== null && typeof defaultValue !== typeof f.value) detail = { value: defaultValue, variationIndex: null, reason: { kind: "ERROR", errorKind: "WRONG_TYPE" } };
    else detail = { value: f.value as T, variationIndex: f.variation, reason: f.reason ?? null };
    return detail;
  }

  /** @internal Record the analytics event for an evaluation made with peekVariationDetail(). */
  recordEvaluation<T extends FlagValue>(key: string, defaultValue: T, detail: EvaluationDetail<T>) {
    const f = this.flag(key);
    this.events?.recordEvaluation({ key, context: this.context, value: detail.value, default: defaultValue, variation: detail.variationIndex, version: f?.version, reason: f?.reason, trackEvents: f?.trackEvents });
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

  /**
   * Switch to a different context (e.g. after login). Resolves with the new flags. When calls
   * overlap, the last one wins: an earlier call's late response is ignored.
   */
  async identify(context: ContextInput, opts: { hash?: string } = {}): Promise<Record<string, FlagValue>> {
    this.contextSeq++;
    this.context = context;
    if (opts.hash !== undefined) this.options.hash = opts.hash;
    if (this.options.offline || this.closed) return this.allFlags();
    this.events?.identify(context);
    // Drop the old context's stream now, so none of its events land after the switch.
    this.stream?.restart();
    await this.loadFlags();
    return this.allFlags();
  }

  getContext(): ContextInput {
    return this.context;
  }

  /** Record a custom event for metrics and experiments. */
  track(key: string, data?: unknown, metricValue?: number) {
    this.events?.track(key, this.context, data, metricValue);
  }

  /**
   * Events: "ready", "failed" (fatal, e.g. an invalid client-side ID), "change" / "change:<key>",
   * "stale" (stream lost; the last flags keep serving) and "recovered".
   */
  on(event: "ready" | "failed" | "change" | "stale" | "recovered" | `change:${string}`, fn: Listener) {
    let set = this.listeners.get(event);
    if (!set) this.listeners.set(event, (set = new Set()));
    set.add(fn);
    return () => this.off(event, fn);
  }

  off(event: string, fn: Listener) {
    const set = this.listeners.get(event);
    if (set?.delete(fn) && !set.size) this.listeners.delete(event);
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
    this.detachVisibility?.();
    this.detachVisibility = null;
    this.stream?.stop();
    await this.events?.close();
    this.listeners.clear();
  }
}

export function createClient(clientSideId: string, context: ContextInput, options: ClientOptions): DevPulseClient {
  return new DevPulseClient(clientSideId, context, options);
}
