import { createHmac } from "node:crypto";
import { EventEmitter } from "node:events";
import { Evaluator, MemoryStore, evaluateFlag, parseContext, type ContextInput, type EvaluationDetail, type FlagConfig, type FlagValue, type SegmentConfig } from "./engine/index.js";
import { EventProcessor, SseClient, noopLogger, type Logger } from "./common/index.js";
import { assertSecureUrl } from "../config.js";

export type { ContextInput, EvaluationDetail, FlagValue, Logger };

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
  /** Pass to the browser SDK's `bootstrap` option for flicker-free SSR. */
  toJSON(): Record<string, { value: FlagValue; variation: number | null; version: number; reason?: unknown }>;
}

/**
 * Server-side client. One instance per process and SDK key.
 *
 *   const client = init(process.env.DEVPULSE_SDK_KEY!, { baseUrl });
 *   await client.waitForInitialization({ timeoutMs: 5000 });
 *   const enabled = await client.variation("new-checkout", { key: user.id, email: user.email }, false);
 */
export class DevPulseNodeClient extends EventEmitter {
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
    return { authorization: this.sdkKey, "user-agent": "DevPulseNode/0.1.0" };
  }

  private startStreaming() {
    this.stream = new SseClient({
      url: `${this.base}/sdk/v1/server/stream`,
      headers: () => this.headers(),
      fetch: this.options.fetch,
      onOpen: () => {
        this.streamFailures = 0;
        this.stopPolling();
      },
      onEvent: (ev) => this.onStreamEvent(ev.type, ev.data),
      onError: (err) => {
        this.logger.warn(`DevPulse stream error: ${err.message}`);
        if (err.status === 401 || err.status === 403) {
          this.fail(new Error("Invalid SDK key"));
          return false;
        }
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
    const poll = async () => {
      try {
        const res = await (this.options.fetch ?? fetch)(`${this.base}/sdk/v1/server/flags`, { headers: { ...this.headers(), ...(this.etag ? { "if-none-match": this.etag } : {}) } });
        if (res.status === 304) return this.markReady();
        if (res.status === 401 || res.status === 403) return this.fail(new Error("Invalid SDK key"));
        if (!res.ok) throw new Error(`Poll failed with ${res.status}`);
        this.etag = res.headers.get("etag");
        this.applyPut((await res.json()) as { flags: Record<string, ServerFlag>; segments: Record<string, SegmentConfig> });
      } catch (err) {
        this.logger.warn("DevPulse poll failed", err);
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
        const isFlag = kind === "flags";
        const prev = isFlag ? this.store.getFlag(key!) : this.store.getSegment(key!);
        if (type === "patch") this.store.upsert(isFlag ? "flag" : "segment", payload.data);
        else if (!prev || prev.version < payload.version) (isFlag ? this.store.flags : this.store.segments).delete(key!);
        if (isFlag) this.emitUpdate(key!);
        else for (const f of this.store.flags.values()) if (JSON.stringify(f.rules).includes(`"${key}"`)) this.emitUpdate(f.key);
      }
    } catch (err) {
      this.logger.error("Malformed stream event", err);
    }
  }

  private applyPut(data: { flags: Record<string, ServerFlag>; segments: Record<string, SegmentConfig> }) {
    const before = new Map([...this.store.flags.entries()].map(([k, f]) => [k, f.version]));
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

  private fail(err: Error) {
    if (!this.initialized) this.rejectReady(err);
    this.emit("failed", err);
  }

  // ---------- Public API ----------

  waitForInitialization(opts: { timeoutMs?: number } = {}): Promise<this> {
    const ready = this.ready.then(() => this);
    if (!opts.timeoutMs) return ready;
    return Promise.race([ready, new Promise<this>((_, rej) => setTimeout(() => rej(new Error("DevPulse initialization timed out")), opts.timeoutMs).unref?.())]);
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
   * Evaluate every flag for a context, e.g. to bootstrap a browser client
   * during server rendering. Doesn't record analytics.
   */
  async allFlagsState(context: ContextInput, opts: { clientSideOnly?: boolean; withReasons?: boolean } = {}): Promise<AllFlagsState> {
    let ctx;
    try {
      ctx = parseContext(context);
    } catch {
      return { valid: false, values: {}, toJSON: () => ({}) };
    }
    const evaluator = new Evaluator(this.store);
    const state: Record<string, { value: FlagValue; variation: number | null; version: number; reason?: unknown }> = {};
    for (const f of this.store.flags.values() as IterableIterator<ServerFlag>) {
      if (opts.clientSideOnly && !f.clientSide) continue;
      const { detail } = evaluator.evaluate(f, ctx);
      state[f.key] = { value: detail.value, variation: detail.variationIndex, version: f.version, ...(opts.withReasons ? { reason: detail.reason } : {}) };
    }
    return { valid: this.initialized, values: Object.fromEntries(Object.entries(state).map(([k, v]) => [k, v.value])), toJSON: () => state };
  }

  /** Secure mode hash for a context, for the browser SDK's `hash` option. */
  secureModeHash(context: ContextInput): string {
    return createHmac("sha256", this.sdkKey).update(parseContext(context).canonicalKey).digest("hex");
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
