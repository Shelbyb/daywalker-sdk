/**
 * Server-Sent Events over fetch, implementing the WHATWG HTML event-stream
 * interpretation (§9.2.6): CRLF/LF/CR line endings, comments, `event`, `data`,
 * `id` and `retry` fields. Unlike the browser EventSource it supports custom
 * headers and request bodies and runs in Node, browsers, workers and React Native.
 */
export interface SseEvent {
  type: string;
  data: string;
  lastEventId: string;
}

/** Default cap on one event (its pending line plus its `data` lines), in UTF-16 code units. */
export const DEFAULT_MAX_EVENT_SIZE = 1024 * 1024;

/**
 * Incremental parser: feed it chunks of text, get dispatched events back. Use one parser per
 * connection: a dropped connection can leave a half-received event behind.
 */
export class SseParser {
  private buffer = "";
  private data: string[] = [];
  private dataSize = 0;
  private eventType = "";
  private sawFirstChunk = false;
  /** The previous chunk ended in CR, so an LF starting this chunk completes a CRLF. */
  private pendingCR = false;
  lastEventId = "";
  retry: number | null = null;

  /** @param maxEventSize feed() throws an SseError once an event grows past this (bounded memory). */
  constructor(private readonly maxEventSize = DEFAULT_MAX_EVENT_SIZE) {}

  feed(chunk: string): SseEvent[] {
    if (!this.sawFirstChunk) {
      this.sawFirstChunk = true;
      if (chunk.charCodeAt(0) === 0xfeff) chunk = chunk.slice(1); // strip BOM
    }
    if (this.pendingCR && chunk.startsWith("\n")) chunk = chunk.slice(1);
    this.pendingCR = false;
    // The pending buffer never holds a line ending, so only the new chunk needs scanning
    // (a long line arriving in many small chunks stays linear, not quadratic).
    const scanFrom = this.buffer.length;
    this.buffer += chunk;
    const out: SseEvent[] = [];
    // Reading the concatenated buffer would flatten it on every chunk, so skip that when the chunk ends no line.
    if (!chunk.includes("\n") && !chunk.includes("\r")) {
      this.checkSize();
      return out;
    }
    // Lines end with CRLF, LF or CR. A CR ends the line immediately (so events
    // dispatch without waiting for more bytes); an LF right after it is skipped.
    let start = 0;
    for (let i = scanFrom; i < this.buffer.length; i++) {
      const c = this.buffer[i];
      if (c !== "\n" && c !== "\r") continue;
      const line = this.buffer.slice(start, i);
      if (c === "\r") {
        if (i === this.buffer.length - 1) this.pendingCR = true;
        else if (this.buffer[i + 1] === "\n") i++;
      }
      start = i + 1;
      const ev = this.line(line);
      if (ev) out.push(ev);
    }
    this.buffer = this.buffer.slice(start);
    this.checkSize();
    return out;
  }

  private checkSize() {
    if (this.buffer.length + this.dataSize > this.maxEventSize) {
      this.buffer = "";
      this.data = [];
      this.dataSize = 0;
      throw new SseError(`Stream event exceeded ${this.maxEventSize} characters`);
    }
  }

  private line(line: string): SseEvent | null {
    if (line === "") {
      if (!this.data.length) {
        this.eventType = "";
        return null;
      }
      const ev = { type: this.eventType || "message", data: this.data.join("\n"), lastEventId: this.lastEventId };
      this.data = [];
      this.dataSize = 0;
      this.eventType = "";
      return ev;
    }
    if (line.startsWith(":")) return null;
    const colon = line.indexOf(":");
    const field = colon === -1 ? line : line.slice(0, colon);
    let value = colon === -1 ? "" : line.slice(colon + 1);
    if (value.startsWith(" ")) value = value.slice(1);
    switch (field) {
      case "event":
        this.eventType = value;
        break;
      case "data":
        this.data.push(value);
        this.dataSize += value.length + 1;
        if (this.dataSize > this.maxEventSize) {
          this.data = [];
          this.dataSize = 0;
          throw new SseError(`Stream event exceeded ${this.maxEventSize} characters`);
        }
        break;
      case "id":
        if (!value.includes("\0")) this.lastEventId = value;
        break;
      case "retry":
        if (/^\d+$/.test(value)) this.retry = Number(value);
        break;
    }
    return null;
  }
}

export interface SseClientOptions {
  url: string | (() => string);
  headers?: Record<string, string> | (() => Record<string, string>);
  fetch?: typeof fetch;
  /** Called for every dispatched event. */
  onEvent: (event: SseEvent) => void;
  onOpen?: () => void;
  /** Called on each failure; return false to stop reconnecting (e.g. 401). */
  onError?: (error: SseError) => boolean | void;
  initialRetryMs?: number;
  maxRetryMs?: number;
  /** Reconnect if nothing (not even a heartbeat) arrives for this long. */
  readTimeoutMs?: number;
  /** Largest single event accepted (default 1 MB); a bigger one drops the connection. */
  maxEventSize?: number;
  /**
   * Send only CORS-safelisted request headers: no `cache-control` or `last-event-id`, which
   * would trigger a preflight that DevPulse doesn't allow. Default: true in browsers and workers.
   */
  browser?: boolean;
}

/** Lower bound for a server-sent `retry:` hint, so `retry: 0` can't cause a reconnect storm. */
export const MIN_SERVER_RETRY_MS = 1000;

/** Browsers and web workers enforce CORS on fetch; Node, Deno (no document), Bun and React Native don't. */
function isBrowserLike(): boolean {
  const g = globalThis as { document?: unknown; WorkerGlobalScope?: unknown };
  return typeof g.document !== "undefined" || typeof g.WorkerGlobalScope !== "undefined";
}

/** Let a timer not keep a Node/Deno/Bun process alive (no-op in browsers). */
function unref(t: ReturnType<typeof setTimeout>) {
  (t as { unref?: () => void }).unref?.();
  return t;
}

export class SseError extends Error {
  constructor(
    message: string,
    readonly status?: number,
  ) {
    super(message);
  }
  /** 4xx (except 408/429) won't succeed on retry. */
  get recoverable() {
    return this.status === undefined || this.status >= 500 || this.status === 408 || this.status === 429;
  }
}

/** Exponential backoff with full jitter, reset after a stable connection. */
export function backoffDelay(attempt: number, base: number, max: number) {
  const exp = Math.min(max, base * 2 ** Math.min(attempt, 10));
  return Math.round(exp / 2 + Math.random() * (exp / 2));
}

export class SseClient {
  private controller: AbortController | null = null;
  private stopped = false;
  private attempt = 0;
  /** Carried across connections; the parser itself is fresh per connection. */
  private lastEventId = "";
  private retry: number | null = null;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private watchdog: ReturnType<typeof setTimeout> | null = null;
  private reader: ReadableStreamDefaultReader<Uint8Array> | null = null;

  constructor(private readonly opts: SseClientOptions) {}

  start() {
    this.stopped = false;
    void this.connect();
  }

  stop() {
    this.stopped = true;
    this.clearTimer();
    // Don't leave the read-timeout timer or a pending read keeping the process alive.
    if (this.watchdog) clearTimeout(this.watchdog);
    this.watchdog = null;
    this.controller?.abort();
    void this.reader?.cancel().catch(() => {});
  }

  /** Drop the current connection (or pending reconnect) and reconnect immediately (e.g. after identify). */
  restart() {
    this.clearTimer();
    this.controller?.abort();
    this.attempt = 0;
    this.lastEventId = ""; // the old stream's ids mean nothing to a new context
    if (!this.stopped) void this.connect();
  }

  private clearTimer() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }

  private async connect() {
    if (this.stopped) return;
    this.clearTimer();
    this.controller?.abort(); // never two live connections
    const controller = new AbortController();
    this.controller = controller;
    const parser = new SseParser(this.opts.maxEventSize);
    parser.lastEventId = this.lastEventId;
    parser.retry = this.retry;
    const f = this.opts.fetch ?? fetch;
    const resetWatchdog = () => {
      if (this.watchdog) clearTimeout(this.watchdog);
      this.watchdog = unref(setTimeout(() => controller.abort(), this.opts.readTimeoutMs ?? 5 * 60_000));
    };
    const connectedAt = Date.now();
    try {
      const url = typeof this.opts.url === "function" ? this.opts.url() : this.opts.url;
      const headers = typeof this.opts.headers === "function" ? this.opts.headers() : (this.opts.headers ?? {});
      const browser = this.opts.browser ?? isBrowserLike();
      resetWatchdog();
      const res = await f(url, {
        headers: {
          accept: "text/event-stream",
          ...(browser ? {} : { "cache-control": "no-cache", ...(this.lastEventId ? { "last-event-id": this.lastEventId } : {}) }),
          ...headers,
        },
        // Browsers: keep the HTTP cache out of it without a non-safelisted request header.
        ...(browser ? { cache: "no-store" as RequestCache } : {}),
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new SseError(`Stream request failed with ${res.status}`, res.status);
      if (this.controller !== controller) {
        void res.body.cancel().catch(() => {});
        return;
      }
      this.opts.onOpen?.();
      const reader = res.body.getReader();
      this.reader = reader;
      const decoder = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        resetWatchdog();
        const events = parser.feed(decoder.decode(value, { stream: true }));
        this.lastEventId = parser.lastEventId;
        this.retry = parser.retry;
        for (const ev of events) {
          if (this.stopped || this.controller !== controller) return; // superseded by restart()/stop() from a handler
          this.opts.onEvent(ev);
        }
      }
      throw new SseError("Stream closed by server");
    } catch (err) {
      if (this.controller === controller && this.watchdog) clearTimeout(this.watchdog);
      if (this.stopped || this.controller !== controller) return;
      controller.abort(); // release the response body
      const e = err instanceof SseError ? err : new SseError((err as Error)?.message ?? "Stream error");
      const keepGoing = this.opts.onError?.(e);
      if (keepGoing === false || !e.recoverable || this.stopped || this.controller !== controller) return;
      if (Date.now() - connectedAt > 60_000) this.attempt = 0; // was healthy for a while
      const fromServer = this.retry !== null;
      const base = fromServer ? Math.max(MIN_SERVER_RETRY_MS, this.retry!) : (this.opts.initialRetryMs ?? 1000);
      let delay = backoffDelay(this.attempt++, base, this.opts.maxRetryMs ?? 30_000);
      if (fromServer) delay = Math.max(MIN_SERVER_RETRY_MS, delay);
      this.timer = unref(setTimeout(() => void this.connect(), delay));
    }
  }
}
