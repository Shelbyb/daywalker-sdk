import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { DEFAULT_MAX_EVENT_SIZE, EventProcessor, MAX_EVENTS_PER_REQUEST, MAX_REQUEST_BYTES, MIN_SERVER_RETRY_MS, SseClient, SseParser, chunkEvents, encodeContext } from "../src/flags/common/index.js";

const parse = (...chunks: string[]) => {
  const p = new SseParser();
  return chunks.flatMap((c) => p.feed(c));
};

describe("SseParser (WHATWG HTML §9.2.6)", () => {
  it("parses multi-line data and ignores comments", () => {
    // Spec example: "data: YHOO\ndata: +2\ndata: 10\n\n"
    expect(parse(": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event\n\n")).toEqual([
      { type: "message", data: "first event", lastEventId: "1" },
      { type: "message", data: "second event", lastEventId: "" },
      { type: "message", data: " third event", lastEventId: "" },
    ]);
    expect(parse("data: YHOO\ndata: +2\ndata: 10\n\n")).toEqual([{ type: "message", data: "YHOO\n+2\n10", lastEventId: "" }]);
  });

  it("handles empty data fields as in the spec example", () => {
    expect(parse("data\n\ndata\ndata\n\ndata:\n")).toEqual([
      { type: "message", data: "", lastEventId: "" },
      { type: "message", data: "\n", lastEventId: "" },
    ]);
  });

  it("supports CRLF, CR and LF and chunk boundaries anywhere (including mid-CRLF)", () => {
    expect(parse("event: put\r", "\ndata: {\"a\":1}\r\n\r\n", "event: patch\rdata: x\r\r")).toEqual([
      { type: "put", data: '{"a":1}', lastEventId: "" },
      { type: "patch", data: "x", lastEventId: "" },
    ]);
    expect(parse("da", "ta: sp", "lit\n", "\n")).toEqual([{ type: "message", data: "split", lastEventId: "" }]);
  });

  it("strips a leading BOM, reads retry, ignores ids with NUL", () => {
    const p = new SseParser();
    expect(p.feed("﻿retry: 2500\nid: a\0b\ndata: x\n\n")).toEqual([{ type: "message", data: "x", lastEventId: "" }]);
    expect(p.retry).toBe(2500);
    p.feed("retry: soon\n");
    expect(p.retry).toBe(2500);
  });

  it("resets the event type after dispatch", () => {
    expect(parse("event: a\ndata: 1\n\ndata: 2\n\n").map((e) => e.type)).toEqual(["a", "message"]);
  });
});

describe("EventProcessor", () => {
  it("redacts private attributes and summarizes evaluations", async () => {
    const sent: unknown[] = [];
    const ep = new EventProcessor({
      url: "http://x/events",
      privateAttributes: ["email"],
      flushIntervalMs: 1_000_000,
      fetch: (async (_u: string, init: { body: string }) => {
        sent.push(...JSON.parse(init.body));
        return new Response(null, { status: 202 });
      }) as unknown as typeof fetch,
    });
    const context = { key: "u1", email: "a@b.c", name: "Ada", _meta: { privateAttributes: ["name"] } };
    for (let i = 0; i < 3; i++) ep.recordEvaluation({ key: "f", context, value: true, default: false, variation: 0, version: 4 });
    ep.recordEvaluation({ key: "missing", context, value: false, default: false, variation: null });
    ep.track("purchase", context, undefined, 9.5);
    await ep.close();
    const index = sent.find((e) => (e as { kind: string }).kind === "index") as { context: Record<string, unknown> };
    expect(index.context).toEqual({ key: "u1", redactedAttributes: ["email", "name"] });
    const summary = sent.find((e) => (e as { kind: string }).kind === "summary") as { features: Record<string, { counters: unknown[] }> };
    expect(summary.features.f?.counters).toEqual([{ variation: 0, version: 4, value: true, count: 3 }]);
    expect(summary.features.missing?.counters).toEqual([{ unknown: true, value: false, count: 1 }]);
    expect(sent.filter((e) => (e as { kind: string }).kind === "index")).toHaveLength(1);
    expect(sent.find((e) => (e as { kind: string }).kind === "custom")).toMatchObject({ key: "purchase", contextKeys: { user: "u1" }, metricValue: 9.5 });
  });
});

describe("encodeContext", () => {
  it("produces base64url JSON that round-trips unicode", () => {
    const enc = encodeContext({ key: "ü/+?" });
    expect(enc).not.toMatch(/[+/=]/);
    expect(JSON.parse(Buffer.from(enc, "base64url").toString("utf8"))).toEqual({ key: "ü/+?" });
  });
});

// ---------- SseClient ----------

type Init = RequestInit & { headers: Record<string, string> };
const enc = new TextEncoder();
const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** A fake fetch: each call runs the next scripted connection. */
function scriptedFetch(script: ((init: Init, n: number) => Response | Promise<Response>)[]) {
  const calls: Init[] = [];
  const open = new Set<number>();
  const f = (async (_url: string, init: Init) => {
    const n = calls.push(init);
    open.add(n);
    init.signal?.addEventListener("abort", () => open.delete(n));
    const step = script[Math.min(n - 1, script.length - 1)]!;
    return step(init, n);
  }) as unknown as typeof fetch;
  return { f, calls, open };
}
const body = (chunks: string[], close = true) =>
  new Response(
    new ReadableStream<Uint8Array>({
      start(c) {
        for (const ch of chunks) c.enqueue(enc.encode(ch));
        if (close) c.close();
      },
    }),
  );

describe("SseClient", () => {
  it("starts every connection with a fresh parser (a half-received event is discarded)", async () => {
    const s = scriptedFetch([() => body(['id: 7\nretry: 1\nevent: patch\ndata: {"half":'], true), () => body(['event: put\ndata: {"a":1}\n\n'], false)]);
    const got: unknown[] = [];
    const c = new SseClient({ url: "http://x/s", fetch: s.f, browser: false, onEvent: (e) => got.push(e), onError: () => true });
    c.start();
    await wait(1300); // server retry hint (1 ms) is raised to the 1 s floor
    c.stop();
    expect(got).toEqual([{ type: "put", data: '{"a":1}', lastEventId: "7" }]);
    // Last-Event-ID survives the reconnect (Node: no CORS).
    expect(s.calls[1]!.headers["last-event-id"]).toBe("7");
  });

  it("restart() during backoff cancels the pending reconnect and keeps one live connection", async () => {
    const s = scriptedFetch([
      () => {
        throw new TypeError("network down");
      },
      () => body([], false),
    ]);
    const c = new SseClient({ url: "http://x/s", fetch: s.f, initialRetryMs: 100, maxRetryMs: 100, onEvent() {}, onError: () => true });
    c.start();
    await wait(10);
    c.restart();
    await wait(250);
    expect(s.calls).toHaveLength(2);
    expect([...s.open]).toEqual([2]);
    c.stop();
    expect([...s.open]).toEqual([]);
  });

  it("restart() aborts the previous connection", async () => {
    const s = scriptedFetch([() => body([], false)]);
    const c = new SseClient({ url: "http://x/s", fetch: s.f, onEvent() {}, onError: () => true });
    c.start();
    await wait(5);
    c.restart();
    c.restart();
    await wait(5);
    expect(s.calls).toHaveLength(3);
    expect([...s.open]).toEqual([3]);
    c.stop();
  });

  it("raises a server `retry: 0` to a 1 s floor (no reconnect storm)", async () => {
    const s = scriptedFetch([() => body(["retry: 0\n\n"])]);
    const c = new SseClient({ url: "http://x/s", fetch: s.f, onEvent() {}, onError: () => true });
    c.start();
    await wait(300);
    c.stop();
    expect(s.calls).toHaveLength(1);
    expect(MIN_SERVER_RETRY_MS).toBe(1000);
  });

  it("drops a connection whose event outgrows maxEventSize", async () => {
    const errors: string[] = [];
    const s = scriptedFetch([() => body(["data: " + "x".repeat(100) + "\n", "data: " + "y".repeat(100) + "\n"], false), () => body([], false)]);
    const c = new SseClient({ url: "http://x/s", fetch: s.f, maxEventSize: 150, initialRetryMs: 1, maxRetryMs: 1, onEvent() {}, onError: (e) => void errors.push(e.message) });
    c.start();
    await wait(30);
    c.stop();
    expect(errors[0]).toMatch(/exceeded 150/);
    expect(s.calls.length).toBeGreaterThan(1);
    // A single line without a newline is capped too.
    expect(() => new SseParser(10).feed("data: " + "z".repeat(20))).toThrow(/exceeded 10/);
    expect(DEFAULT_MAX_EVENT_SIZE).toBe(1024 * 1024);
  });

  it("sends only CORS-safelisted headers in browsers", async () => {
    const s = scriptedFetch([() => body(["id: 1\n\n"]), () => body([], false)]);
    const c = new SseClient({ url: "http://x/s", fetch: s.f, browser: true, headers: { authorization: "k" }, initialRetryMs: 1, maxRetryMs: 1, onEvent() {}, onError: () => true });
    c.start();
    await wait(30);
    c.stop();
    for (const init of s.calls) {
      expect(Object.keys(init.headers).sort()).toEqual(["accept", "authorization"]);
      expect(init.cache).toBe("no-store");
    }
    expect(s.calls.length).toBeGreaterThan(1);
  });

  it("detects browsers by `document` and sends cache-control elsewhere", async () => {
    const g = globalThis as { document?: unknown };
    const s = scriptedFetch([() => body([], false)]);
    g.document = {};
    try {
      const c = new SseClient({ url: "http://x/s", fetch: s.f, onEvent() {} });
      c.start();
      await wait(5);
      c.stop();
    } finally {
      delete g.document;
    }
    const n = new SseClient({ url: "http://x/s", fetch: s.f, onEvent() {} });
    n.start();
    await wait(5);
    n.stop();
    expect(s.calls[0]!.headers["cache-control"]).toBeUndefined();
    expect(s.calls[1]!.headers["cache-control"]).toBe("no-cache");
  });

  it("doesn't keep a Node process alive with its watchdog or backoff timers", async () => {
    const s = scriptedFetch([
      () => {
        throw new TypeError("refused");
      },
    ]);
    const c = new SseClient({ url: "http://x/s", fetch: s.f, onEvent() {}, onError: () => true });
    c.start();
    await wait(5);
    const timers = c as unknown as { timer: { hasRef(): boolean } | null; watchdog: { hasRef(): boolean } | null };
    expect(timers.timer?.hasRef()).toBe(false);
    expect(timers.watchdog?.hasRef()).toBe(false);
    c.stop();
  });
});

describe("chunkEvents", () => {
  it("splits at 5000 events and ~500 KB per request", () => {
    const small = Array.from({ length: 12_001 }, (_, i) => ({ kind: "custom", key: `e${i}` }));
    const bodies = chunkEvents(small);
    expect(bodies.map((b) => (JSON.parse(b) as unknown[]).length)).toEqual([5000, 5000, 2001]);
    const big = Array.from({ length: 30 }, (_, i) => ({ kind: "custom", key: `e${i}`, data: "é".repeat(20_000) })); // ~40 KB each
    const chunks = chunkEvents(big);
    expect(chunks.length).toBeGreaterThan(2);
    for (const b of chunks) expect(Buffer.byteLength(b)).toBeLessThan(MAX_REQUEST_BYTES + 1);
    expect(chunks.flatMap((b) => JSON.parse(b) as unknown[])).toHaveLength(30);
    expect(MAX_EVENTS_PER_REQUEST).toBe(5000);
  });

  it("drops a single event bigger than a request", () => {
    const warned: unknown[] = [];
    const logger = { debug() {}, info() {}, error() {}, warn: (...a: unknown[]) => void warned.push(a) };
    expect(chunkEvents([{ kind: "custom", data: "x".repeat(600_000) }, { kind: "custom" }], logger)).toEqual(['[{"kind":"custom"}]']);
    expect(warned).toHaveLength(1);
  });
});

describe("EventProcessor flush", () => {
  it("posts at most 5000 events per request and only small bodies with keepalive", async () => {
    const posts: { count: number; keepalive: boolean | undefined }[] = [];
    const ep = new EventProcessor({
      url: "http://x/events",
      flushIntervalMs: 1_000_000,
      fetch: (async (_u: string, init: RequestInit) => {
        posts.push({ count: (JSON.parse(String(init.body)) as unknown[]).length, keepalive: init.keepalive });
        return new Response(null, { status: 202 });
      }) as unknown as typeof fetch,
    });
    for (let i = 0; i < 9000; i++) ep.track(`k${i}`, { key: "u1" });
    ep.track("one", { key: "u2" });
    await ep.close();
    expect(posts.reduce((n, p) => n + p.count, 0)).toBe(9001 + 2); // custom events + one index event per context
    for (const p of posts) expect(p.count).toBeLessThan(5001);
    expect(posts.filter((p) => p.keepalive)).toHaveLength(0); // all bodies here are > 60 KB
  });
});
