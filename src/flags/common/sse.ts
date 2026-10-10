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

/** Incremental parser: feed it chunks of text, get dispatched events back. */
export class SseParser {
  private buffer = "";
  private data: string[] = [];
  private eventType = "";
  private sawFirstChunk = false;
  /** The previous chunk ended in CR, so an LF starting this chunk completes a CRLF. */
  private pendingCR = false;
  lastEventId = "";
  retry: number | null = null;

  feed(chunk: string): SseEvent[] {
    if (!this.sawFirstChunk) {
      this.sawFirstChunk = true;
      if (chunk.charCodeAt(0) === 0xfeff) chunk = chunk.slice(1); // strip BOM
    }
    if (this.pendingCR && chunk.startsWith("\n")) chunk = chunk.slice(1);
    this.pendingCR = false;
    this.buffer += chunk;
    const out: SseEvent[] = [];
    // Lines end with CRLF, LF or CR. A CR ends the line immediately (so events
    // dispatch without waiting for more bytes); an LF right after it is skipped.
    let start = 0;
    for (let i = 0; i < this.buffer.length; i++) {
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
    return out;
  }

  private line(line: string): SseEvent | null {
    if (line === "") {
      if (!this.data.length) {
        this.eventType = "";
        return null;
      }
      const ev = { type: this.eventType || "message", data: this.data.join("\n"), lastEventId: this.lastEventId };
      this.data = [];
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
  private parser = new SseParser();
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
    if (this.timer) clearTimeout(this.timer);
    // Don't leave the read-timeout timer or a pending read keeping the process alive.
    if (this.watchdog) clearTimeout(this.watchdog);
    this.controller?.abort();
    void this.reader?.cancel().catch(() => {});
  }

  /** Drop the current connection and reconnect immediately (e.g. after identify). */
  restart() {
    this.controller?.abort();
    this.attempt = 0;
    this.parser = new SseParser();
    if (!this.stopped) void this.connect();
  }

  private async connect() {
    if (this.stopped) return;
    const controller = new AbortController();
    this.controller = controller;
    const f = this.opts.fetch ?? fetch;
    const resetWatchdog = () => {
      if (this.watchdog) clearTimeout(this.watchdog);
      this.watchdog = setTimeout(() => controller.abort(), this.opts.readTimeoutMs ?? 5 * 60_000);
    };
    const connectedAt = Date.now();
    try {
      const url = typeof this.opts.url === "function" ? this.opts.url() : this.opts.url;
      const headers = typeof this.opts.headers === "function" ? this.opts.headers() : (this.opts.headers ?? {});
      resetWatchdog();
      const res = await f(url, {
        headers: { accept: "text/event-stream", "cache-control": "no-cache", ...(this.parser.lastEventId ? { "last-event-id": this.parser.lastEventId } : {}), ...headers },
        signal: controller.signal,
      });
      if (!res.ok || !res.body) throw new SseError(`Stream request failed with ${res.status}`, res.status);
      this.opts.onOpen?.();
      const reader = res.body.getReader();
      this.reader = reader;
      const decoder = new TextDecoder();
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        resetWatchdog();
        for (const ev of this.parser.feed(decoder.decode(value, { stream: true }))) this.opts.onEvent(ev);
      }
      throw new SseError("Stream closed by server");
    } catch (err) {
      if (this.watchdog) clearTimeout(this.watchdog);
      if (this.stopped || (controller.signal.aborted && this.controller !== controller)) return;
      const e = err instanceof SseError ? err : new SseError((err as Error)?.message ?? "Stream error");
      const keepGoing = this.opts.onError?.(e);
      if (keepGoing === false || !e.recoverable) return;
      if (Date.now() - connectedAt > 60_000) this.attempt = 0; // was healthy for a while
      const base = this.parser.retry ?? this.opts.initialRetryMs ?? 1000;
      const delay = backoffDelay(this.attempt++, base, this.opts.maxRetryMs ?? 30_000);
      this.timer = setTimeout(() => void this.connect(), delay);
    }
  }
}
