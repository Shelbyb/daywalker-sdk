import { Evaluator, MemoryStore, evaluateFlag, parseContext, type ContextInput, type EvaluationDetail, type FlagConfig, type FlagValue, type SegmentConfig } from "./engine/index.js";
import { Emitter } from "./common/emitter.js";
import { hmacSha256Hex } from "./common/hmac.js";
import { EventProcessor, SDK_VERSION, SseClient, noopLogger, requestTimeout, type Logger } from "./common/index.js";
import type { FlagSet } from "./client.js";
import { assertSecureUrl } from "../secure-url.js";

export type { ContextInput, EvaluationDetail, FlagSet, FlagValue, Logger };
export { SDK_VERSION };

export interface NodeClientOptions {
  /** Base URL of your DevPulse deployment (https required except on localhost). */
  baseUrl: string;
  /** Real-time updates over SSE (default). Set false to poll instead. */
  stream?: boolean;
  /** Poll interval when not streaming (and as a fallback). Minimum 30s. */
  pollIntervalMs?: number;
  sendEvents?: boolean;
  flushIntervalMs?: number;
  privateAttributes?: string[];
  allAttributesPrivate?: boolean;
  /** Never connect; every variation returns its default (useful in tests). */
  offline?: boolean;
  /** Start from fixed data (e.g. tests or a file); disables network. */
  initialData?: { flags?: Record<string, FlagConfig>; segments?: Record<string, SegmentConfig> };
  fetch?: typeof fetch;
  logger?: Logger;
}

type ServerFlag = FlagConfig & { clientSide?: boolean; mobile?: boolean };

export interface AllFlagsState {
  valid: boolean;
  values: Record<string, FlagValue>;
  /** Pass to the browser SDK's `bootstrap` option for flicker-free SSR (same shape as the client endpoint). */
  toJSON(): FlagSet;
}

export interface AllFlagsStateOptions {
  /**
   * Only flags marked "available to client-side SDKs" (default true), so the result is safe to
   * embed in HTML. Pass false to include every flag, e.g. for server-side use only.
   */
  clientSideOnly?: boolean;
  /** Include evaluation reasons (always included for experiments). */
  withReasons?: boolean;
}

/**
 * Server-side client. One instance per process and SDK key.
 *
 * Events: "ready", "failed" (fatal, e.g. an invalid SDK key), "update" / "update:<key>",
 * "stale" (connection lost; the last data keeps serving) and "recovered".
 *
 *   const client = init(process.env.DEVPULSE_SDK_KEY!, { baseUrl });
 *   await client.waitForInitialization({ timeoutMs: 5000 });
 *   const enabled = await client.variation("new-checkout", { key: user.id, email: user.email }, false);
 */
export class DevPulseNodeClient extends Emitter {
  private store = new MemoryStore();
  private stream: SseClient | null = null;
  private poller: ReturnType<typeof setInterval> | null = null;
  private etag: string | null = null;
  private events: EventProcessor | null = null;
  private initialized = false;
  private ready: Promise<void>;
  private resolveReady!: () => void;
  private rejectReady!: (e: Error) => void;
  private streamFailures = 0;
  private stale = false;
  private readonly logger: Logger;
  private readonly base: string;

  constructor(
    private readonly sdkKey: string,
    private readonly options: NodeClientOptions,
  ) {
    super();
    this.logger = options.logger ?? noopLogger;
    this.base = options.baseUrl.replace(/\/$/, "");
    this.ready = new Promise((res, rej) => {
      this.resolveReady = res;
      this.rejectReady = rej;
    });
    this.ready.catch(() => undefined);

    if (options.initialData || options.offline) {
      if (options.initialData) this.store.replace(options.initialData);
      this.markReady();
      return;
    }
    // Checked once the SDK key will actually be sent (offline / fixture clients make no requests).
    assertSecureUrl("baseUrl", options.baseUrl);
    if (options.sendEvents !== false) {
      this.events = new EventProcessor({
        url: `${this.base}/sdk/v1/events`,
        headers: { authorization: sdkKey },
        flushIntervalMs: options.flushIntervalMs ?? 5000,
        privateAttributes: options.privateAttributes,
        allAttributesPrivate: options.allAttributesPrivate,
        fetch: options.fetch,
        logger: this.logger,
      });
    }
    if (options.stream === false) this.startPolling();
    else this.startStreaming();
  }

  private headers() {
    return { authorization: this.sdkKey, "user-agent": `DevPulseNode/${SDK_VERSION}` };
  }

  private startStreaming() {
    this.stream = new SseClient({
      url: `${this.base}/sdk/v1/server/stream`,
      headers: () => this.headers(),
      fetch: this.options.fetch,
      browser: false,
      // Full rulesets (segments with big target lists) can be large.
      maxEventSize: 64 * 1024 * 1024,
      onOpen: () => {
        this.streamFailures = 0;
        this.stopPolling();
        this.setStale(false);
      },
      onEvent: (ev) => this.onStreamEvent(ev.type, ev.data),
      onError: (err) => {
        this.logger.warn(`DevPulse stream error: ${err.message}`);
        if (err.status === 401 || err.status === 403) {
          this.fail(new Error("Invalid SDK key"));
          return false;
        }
        // While polling, the poll result decides whether data is stale.
        if (!this.poller) this.setStale(true, err);
        // After repeated failures, poll so data stays fresh while we keep retrying the stream.
        if (++this.streamFailures >= 3) this.startPolling();
        return true;
      },
    });
    this.stream.start();
  }

  private startPolling() {
    if (this.poller) return;
    const interval = Math.max(30_000, this.options.pollIntervalMs ?? 30_000);
    let inFlight = false;
    const poll = async () => {
      // A hung request must not pile up a new one every interval.
      if (inFlight) return;
      inFlight = true;
      const timeout = requestTimeout();
      try {
        const res = await (this.options.fetch ?? fetch)(`${this.base}/sdk/v1/server/flags`, { headers: { ...this.headers(), ...(this.etag ? { "if-none-match": this.etag } : {}) }, signal: timeout.signal });
        if (res.status === 304) {
          this.setStale(false);
          return this.markReady();
        }
        if (res.status === 401 || res.status === 403) {
          this.stopPolling(); // an invalid key won't start working on retry
          return this.fail(new Error("Invalid SDK key"));
        }
        if (!res.ok) throw new Error(`Poll failed with ${res.status}`);
        const etag = res.headers.get("etag");
        this.applyPut((await res.json()) as { flags: Record<string, ServerFlag>; segments: Record<string, SegmentConfig> });
        this.etag = etag;
        this.setStale(false);
      } catch (err) {
        this.logger.warn("DevPulse poll failed", err);
        this.setStale(true, err as Error);
      } finally {
        timeout.clear();
        inFlight = false;
      }
    };
    this.poller = setInterval(poll, interval);
    this.poller.unref?.();
    void poll();
  }

  private stopPolling() {
    if (this.poller) clearInterval(this.poller);
    this.poller = null;
  }

  private onStreamEvent(type: string, data: string) {
    try {
      const payload = JSON.parse(data);
      if (type === "put") this.applyPut(payload.data);
      else if (type === "patch" || type === "delete") {
        const [, kind, key] = String(payload.path).split("/");
        if (!key) throw new Error(`Bad path ${String(payload.path)}`);
        const isFlag = kind === "flags";
        const prev = isFlag ? this.store.getFlag(key) : this.store.getSegment(key);
        if (type === "patch") this.store.upsert(isFlag ? "flag" : "segment", payload.data);
        else if (typeof payload.version === "number" && (!prev || prev.version < payload.version)) {
          // Keep a tombstone so a delayed patch with an older version can't resurrect it.
          const tombstone = { key, version: payload.version, deleted: true } as FlagConfig & SegmentConfig;
          (isFlag ? this.store.flags : this.store.segments).set(key, tombstone);
        }
        if (isFlag) this.emitUpdate(key);
        else for (const f of this.store.flags.values()) if (!f.deleted && JSON.stringify(f.rules).includes(`"${key}"`)) this.emitUpdate(f.key);
      }
    } catch (err) {
      this.logger.error("Malformed stream event", err);
    }
  }

  private applyPut(data: { flags: Record<string, ServerFlag>; segments: Record<string, SegmentConfig> }) {
    const before = new Map([...this.store.flags.entries()].filter(([, f]) => !f.deleted).map(([k, f]) => [k, f.version]));
    this.store.replace(data);
    for (const [k, f] of this.store.flags) if (before.get(k) !== f.version) this.emitUpdate(k);
    for (const k of before.keys()) if (!this.store.flags.has(k)) this.emitUpdate(k);
    this.markReady();
  }

  private emitUpdate(key: string) {
    this.emit("update", { key });
    this.emit(`update:${key}`, { key });
  }

  private markReady() {
    if (this.initialized) return;
    this.initialized = true;
    this.resolveReady();
    this.emit("ready");
  }

  /** "stale" when updates stop arriving (flags keep serving the last data), "recovered" when they resume. */
  private setStale(stale: boolean, err?: Error) {
    if (!this.initialized || this.stale === stale) return;
    this.stale = stale;
    if (stale) this.emit("stale", err);
    else this.emit("recovered");
  }

  private fail(err: Error) {
    if (!this.initialized) this.rejectReady(err);
    this.emit("failed", err);
  }

  // ---------- Public API ----------

  waitForInitialization(opts: { timeoutMs?: number } = {}): Promise<this> {
    const ready = this.ready.then(() => this);
    if (!opts.timeoutMs) return ready;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const timeout = new Promise<this>((_, rej) => {
      // Not unref'd: someone is awaiting it. Cleared as soon as either side settles.
      timer = setTimeout(() => rej(new Error("DevPulse initialization timed out")), opts.timeoutMs);
    });
    return Promise.race([ready, timeout]).finally(() => clearTimeout(timer));
  }

  get isInitialized(): boolean {
    return this.initialized;
  }

  /** Evaluate a flag locally. Never throws; returns `defaultValue` on any problem. */
  variationDetailSync<T extends FlagValue>(key: string, context: ContextInput, defaultValue: T): EvaluationDetail<T> {
    if (!this.initialized) return { value: defaultValue, variationIndex: null, reason: { kind: "ERROR", errorKind: "CLIENT_NOT_READY" } };
    const { prerequisites, ...detail } = evaluateFlag(this.store, key, context, defaultValue);
    const flag = this.store.getFlag(key);
    let out: EvaluationDetail<T> = detail;
    if (detail.reason.kind !== "ERROR" && defaultValue !== null && typeof defaultValue !== typeof detail.value) {
      out = { value: defaultValue, variationIndex: null, reason: { kind: "ERROR", errorKind: "WRONG_TYPE" } };
    }
    if (this.events) {
      for (const p of prerequisites) this.events.recordEvaluation({ key: p.flag.key, context, value: p.detail.value, default: null, variation: p.detail.variationIndex, version: p.flag.version, reason: p.detail.reason, trackEvents: p.flag.trackEvents });
      this.events.recordEvaluation({ key, context, value: out.value, default: defaultValue, variation: out.variationIndex, version: flag?.version, reason: out.reason, trackEvents: flag?.trackEvents });
    }
    return out;
  }

  variationSync<T extends FlagValue>(key: string, context: ContextInput, defaultValue: T): T {
    return this.variationDetailSync(key, context, defaultValue).value;
  }

  async variation<T extends FlagValue>(key: string, context: ContextInput, defaultValue: T): Promise<T> {
    return this.variationSync(key, context, defaultValue);
  }

  async variationDetail<T extends FlagValue>(key: string, context: ContextInput, defaultValue: T): Promise<EvaluationDetail<T>> {
    return this.variationDetailSync(key, context, defaultValue);
  }

  async boolVariation(key: string, context: ContextInput, defaultValue: boolean) {
    return this.variation(key, context, defaultValue);
  }
  async stringVariation(key: string, context: ContextInput, defaultValue: string) {
    return this.variation(key, context, defaultValue);
  }
  async numberVariation(key: string, context: ContextInput, defaultValue: number) {
    return this.variation(key, context, defaultValue);
  }
  async jsonVariation<T extends FlagValue>(key: string, context: ContextInput, defaultValue: T) {
    return this.variation(key, context, defaultValue);
  }

  /**
   * Evaluate every client-side flag for a context, e.g. to bootstrap a browser client
   * during server rendering. Doesn't record analytics.
   *
   *   const state = await client.allFlagsState(context);
   *   createClient(id, context, { baseUrl, bootstrap: state.toJSON() });
   */
  async allFlagsState(context: ContextInput, opts: AllFlagsStateOptions = {}): Promise<AllFlagsState> {
    const clientSideOnly = opts.clientSideOnly ?? true;
    let ctx;
    try {
      ctx = parseContext(context);
    } catch {
      return { valid: false, values: {}, toJSON: () => ({}) };
    }
    const evaluator = new Evaluator(this.store);
    const entries: [string, FlagSet[string]][] = [];
    for (const f of this.store.flags.values() as IterableIterator<ServerFlag>) {
      if (f.deleted || (clientSideOnly && !f.clientSide)) continue;
      const { detail } = evaluator.evaluate(f, ctx);
      // Same shape as the DevPulse client endpoint, so client-side analytics and experiments keep working.
      const inExperiment = "inExperiment" in detail.reason && !!detail.reason.inExperiment;
      entries.push([f.key, {
        value: detail.value,
        variation: detail.variationIndex,
        version: f.version,
        ...(opts.withReasons || inExperiment ? { reason: detail.reason } : {}),
        ...(f.trackEvents || inExperiment ? { trackEvents: true } : {}),
        ...(inExperiment ? { trackReason: true } : {}),
      }]);
    }
    // Own properties only (fromEntries), so a flag key like `__proto__` can't replace the prototype.
    const state: FlagSet = Object.fromEntries(entries);
    return { valid: this.initialized, values: Object.fromEntries(Object.entries(state).map(([k, v]) => [k, v.value])), toJSON: () => state };
  }

  /** Secure mode hash for a context, for the browser SDK's `hash` option. */
  secureModeHash(context: ContextInput): string {
    return hmacSha256Hex(this.sdkKey, parseContext(context).canonicalKey);
  }

  track(key: string, context: ContextInput, data?: unknown, metricValue?: number) {
    this.events?.track(key, context, data, metricValue);
  }

  identify(context: ContextInput) {
    this.events?.identify(context);
  }

  async flush() {
    await this.events?.flush();
  }

  async close() {
    this.stream?.stop();
    this.stopPolling();
    await this.events?.close();
    this.removeAllListeners();
  }
}

export function init(sdkKey: string, options: NodeClientOptions): DevPulseNodeClient {
  return new DevPulseNodeClient(sdkKey, options);
}
