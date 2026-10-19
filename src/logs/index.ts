import { baseUrl, byteLength, DevPulseHttpError, readText, retryAfterSeconds, send, userAgent, type HttpOptions } from "../common/http.js";

/**
 * Structured log shipping to DevPulse (`POST {host}/logs/ingest`, `Authorization: Bearer dpl_…`).
 * Batches in memory, flushes on size or interval, and never throws from `log()`. Fetch only.
 */

export type LogLevel = "trace" | "debug" | "info" | "warn" | "error" | "fatal";
export type LogAttributes = Record<string, unknown>;

/** DevPulse's per-request and per-entry limits (see the logs ingest endpoint). */
export const LOG_LIMITS = {
  /** Largest request body DevPulse accepts. */
  maxBodyBytes: 5 * 1024 * 1024,
  /** Most entries DevPulse keeps from one request. */
  maxEntriesPerRequest: 5000,
  /** Longer messages are clipped. */
  maxMessageChars: 32 * 1024,
  /** Larger serialized attribute objects are replaced by a marker. */
  maxAttributesChars: 16 * 1024,
} as const;

export type LoggerOptions = HttpOptions & {
  /** Your DevPulse URL, e.g. https://devpulse.example.com. */
  host: string;
  /** The log source's ingest token (`dpl_…`). Sent only in the Authorization header. */
  token: string;
  /** Service name stored with every entry. */
  service?: string;
  /** Host name stored with every entry. */
  hostname?: string;
  /** Attributes added to every entry. */
  defaultAttributes?: LogAttributes;
  /** Drop entries below this level. Default "debug". */
  minLevel?: LogLevel;
  /** Flush when this many entries are queued. Default 100. */
  flushAt?: number;
  /** Flush at least this often, in ms. Default 5000; 0 disables the timer. */
  flushIntervalMs?: number;
  /** Oldest entries are dropped beyond this many. Default 10000. */
  maxQueueSize?: number;
  /** Max bytes per request (capped at DevPulse's 5 MB). Default 1 MB. */
  maxBatchBytes?: number;
  /** Retries after 429/5xx/network errors per batch. Default 2. */
  maxRetries?: number;
  onError?: (err: unknown) => void;
  /** Test seams. */
  sleep?: (ms: number) => Promise<void>;
  now?: () => number;
};

const LEVELS: LogLevel[] = ["trace", "debug", "info", "warn", "error", "fatal"];

type Entry = Record<string, unknown>;

export class Logger {
  private readonly url: string;
  readonly #token: string;
  private readonly o: LoggerOptions;
  private queue: string[] = [];
  private timer: ReturnType<typeof setInterval> | undefined;
  private flushing: Promise<void> | null = null;
  private closed = false;
  /** Entries dropped because the queue was full. */
  dropped = 0;

  constructor(options: LoggerOptions) {
    this.url = `${baseUrl("host", options.host)}/logs/ingest`;
    if (!options.token) throw new Error("token is required");
    this.#token = options.token;
    const { token: _drop, ...rest } = options;
    this.o = { ...rest, token: "" };
    const interval = options.flushIntervalMs ?? 5000;
    if (interval > 0) {
      this.timer = setInterval(() => void this.flush(), interval);
      (this.timer as { unref?: () => void }).unref?.();
    }
  }

  toJSON() {
    return { url: this.url, service: this.o.service };
  }

  /** Queue one entry. Never throws. */
  log(level: LogLevel, message: string, attributes?: LogAttributes): void {
    if (this.closed) return;
    if (LEVELS.indexOf(level) < LEVELS.indexOf(this.o.minLevel ?? "debug")) return;
    const attrs = { ...this.o.defaultAttributes, ...attributes };
    let extra: Entry = attrs;
    try {
      const size = JSON.stringify(attrs).length;
      if (size > LOG_LIMITS.maxAttributesChars) extra = { "devpulse.truncated": true, "devpulse.original_size": size };
    } catch {
      extra = { "devpulse.unserializable": true };
    }
    const msg = String(message);
    this.enqueue({
      ...extra,
      ...(this.o.service ? { service: this.o.service } : {}),
      ...(this.o.hostname ? { host: this.o.hostname } : {}),
      timestamp: new Date((this.o.now ?? Date.now)()).toISOString(),
      level,
      message: msg.length > LOG_LIMITS.maxMessageChars ? `${msg.slice(0, LOG_LIMITS.maxMessageChars)}…` : msg,
    });
  }

  /** Queue an already-structured object as is (e.g. a pino line); DevPulse detects its fields. */
  raw(entry: Entry): void {
    if (!this.closed) this.enqueue(entry);
  }

  trace(message: string, attributes?: LogAttributes) {
    this.log("trace", message, attributes);
  }
  debug(message: string, attributes?: LogAttributes) {
    this.log("debug", message, attributes);
  }
  info(message: string, attributes?: LogAttributes) {
    this.log("info", message, attributes);
  }
  warn(message: string, attributes?: LogAttributes) {
    this.log("warn", message, attributes);
  }
  error(message: string, attributes?: LogAttributes) {
    this.log("error", message, attributes);
  }
  fatal(message: string, attributes?: LogAttributes) {
    this.log("fatal", message, attributes);
  }

  /** A logger that adds `attributes` to every entry. Shares this logger's queue. */
  child(attributes: LogAttributes): Pick<Logger, "log" | LogLevel> {
    const log = (level: LogLevel, message: string, a?: LogAttributes) => this.log(level, message, { ...attributes, ...a });
    const at = (level: LogLevel) => (message: string, a?: LogAttributes) => log(level, message, a);
    return { log, trace: at("trace"), debug: at("debug"), info: at("info"), warn: at("warn"), error: at("error"), fatal: at("fatal") } as Pick<Logger, "log" | LogLevel>;
  }

  get queued() {
    return this.queue.length;
  }

  private enqueue(entry: Entry) {
    let line: string;
    try {
      line = JSON.stringify(entry);
    } catch (err) {
      this.o.onError?.(err);
      return;
    }
    this.queue.push(byteLength(line) <= this.maxBatchBytes() ? line : JSON.stringify({ level: "warn", message: "log entry too large, dropped", "devpulse.original_size": line.length }));
    const max = this.o.maxQueueSize ?? 10_000;
    if (this.queue.length > max) {
      this.dropped += this.queue.length - max;
      this.queue.splice(0, this.queue.length - max);
    }
    if (this.queue.length >= (this.o.flushAt ?? 100)) void this.flush();
  }

  private maxBatchBytes() {
    return Math.min(this.o.maxBatchBytes ?? 1024 * 1024, LOG_LIMITS.maxBodyBytes) - 2;
  }

  /** Send everything queued now. Resolves when done; errors go to `onError`. */
  flush(): Promise<void> {
    this.flushing ??= this.drain().finally(() => (this.flushing = null));
    return this.flushing;
  }

  private async drain() {
    const max = this.maxBatchBytes();
    while (this.queue.length) {
      const batch: string[] = [];
      let bytes = 0;
      while (this.queue.length && batch.length < LOG_LIMITS.maxEntriesPerRequest) {
        const size = byteLength(this.queue[0]!) + 1;
        if (batch.length && bytes + size > max) break;
        batch.push(this.queue.shift()!);
        bytes += size;
      }
      await this.post(`[${batch.join(",")}]`);
    }
  }

  private async post(body: string) {
    const retries = this.o.maxRetries ?? 2;
    for (let attempt = 0; ; attempt++) {
      let retryAfter: number | undefined;
      let error: unknown;
      try {
        const res = await send(this.url, { method: "POST", headers: { authorization: `Bearer ${this.#token}`, "content-type": "application/json", "user-agent": userAgent("Logs") }, body }, this.o);
        if (res.ok) {
          await res.body?.cancel().catch(() => {});
          return;
        }
        error = new DevPulseHttpError("Log ingest", res.status, await readText(res, 200), retryAfterSeconds(res));
        if (res.status !== 429 && res.status < 500) {
          // Not retryable (401, 413, …): drop the batch.
          this.o.onError?.(error);
          return;
        }
        retryAfter = retryAfterSeconds(res);
      } catch (err) {
        error = err;
      }
      if (attempt >= retries) {
        this.o.onError?.(error);
        return;
      }
      await (this.o.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms))))(Math.min(retryAfter !== undefined ? retryAfter * 1000 : 500 * 2 ** attempt, 30_000));
    }
  }

  /** Stop the timer, flush what is queued and stop accepting entries. */
  async shutdown(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
    this.closed = true;
  }
}

export function createLogger(options: LoggerOptions) {
  return new Logger(options);
}

/**
 * A console-shaped object (`log`, `info`, `warn`, `error`, `debug`, `trace`) that ships to DevPulse
 * and, optionally, still prints. Extra arguments go into the `args` attribute.
 */
export function consoleAdapter(logger: Logger, options: { passthrough?: Pick<Console, "log" | "info" | "warn" | "error" | "debug" | "trace"> } = {}) {
  const fmt = (args: unknown[]) => {
    const [first, ...rest] = args;
    const message = first instanceof Error ? `${first.name}: ${first.message}` : typeof first === "string" ? first : safeJson(first);
    const attrs: LogAttributes = {};
    if (first instanceof Error && first.stack) attrs.stack = first.stack;
    if (rest.length) attrs.args = rest.map((a) => (a instanceof Error ? { name: a.name, message: a.message, stack: a.stack } : a));
    return [message, attrs] as const;
  };
  const make = (level: LogLevel, method: "log" | "info" | "warn" | "error" | "debug" | "trace") => (...args: unknown[]) => {
    options.passthrough?.[method](...args);
    const [m, a] = fmt(args);
    logger.log(level, m, a);
  };
  return { log: make("info", "log"), info: make("info", "info"), warn: make("warn", "warn"), error: make("error", "error"), debug: make("debug", "debug"), trace: make("trace", "trace") };
}

/**
 * A pino-compatible destination: `pino({}, pinoDestination(logger))`. Each JSON line pino writes is
 * shipped as is (DevPulse maps pino's numeric levels, `msg` and `time`).
 */
export function pinoDestination(logger: Logger) {
  return {
    write(line: string) {
      for (const l of line.split("\n")) {
        if (!l.trim()) continue;
        try {
          const o = JSON.parse(l);
          if (o && typeof o === "object" && !Array.isArray(o)) logger.raw(o as Entry);
          else logger.info(l);
        } catch {
          logger.info(l);
        }
      }
      return true;
    },
  };
}

function safeJson(v: unknown): string {
  try {
    return typeof v === "undefined" ? "undefined" : JSON.stringify(v);
  } catch {
    return String(v);
  }
}
