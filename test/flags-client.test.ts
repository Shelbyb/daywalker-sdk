import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { SDK_VERSION, createClient } from "../src/flags/client.js";
import { SDK_VERSION as VERSION_CONSTANT } from "../src/flags/common/version.js";

/** A fetch that serves one SSE stream we can push events into. */
function streamingFetch() {
  let push!: (s: string) => void;
  const encoder = new TextEncoder();
  const requests: string[] = [];
  const f = (async (url: string) => {
    requests.push(url);
    if (url.includes("/events/")) return new Response(null, { status: 202 });
    const body = new ReadableStream<Uint8Array>({ start: (c) => void (push = (s) => c.enqueue(encoder.encode(s))) });
    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  }) as unknown as typeof fetch;
  return { f, requests, push: (s: string) => push(s) };
}

const tick = () => new Promise((r) => setTimeout(r, 10));

describe("DevPulseClient", () => {
  it("loads via stream put, applies patches and emits changes", async () => {
    const s = streamingFetch();
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x/", fetch: s.f, sendEvents: false });
    await tick();
    expect(s.requests[0]).toMatch(/^https:\/\/x\/sdk\/v1\/client\/cid\/stream\?context=/);
    s.push('event: put\ndata: {"a":{"value":false,"variation":1,"version":1}}\n\n');
    await client.waitForInitialization({ timeoutMs: 1000 });
    expect(client.variation("a", true)).toBe(false);

    const seen: unknown[] = [];
    client.on("change:a", (cur, prev) => seen.push([prev, cur]));
    s.push('event: patch\ndata: {"key":"a","value":true,"variation":0,"version":2}\n\n');
    await tick();
    expect(client.variation("a", false)).toBe(true);
    // Stale versions are ignored.
    s.push('event: patch\ndata: {"key":"a","value":false,"variation":1,"version":1}\n\n');
    await tick();
    expect(client.variation("a", false)).toBe(true);
    expect(seen).toEqual([[false, true]]);
    s.push('event: delete\ndata: {"key":"a","version":3}\n\n');
    await tick();
    expect(client.variationDetail("a", "dflt" as never).reason).toEqual({ kind: "ERROR", errorKind: "FLAG_NOT_FOUND" });
    await client.close();
  });

  it("serves bootstrap values immediately and guards types", async () => {
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", streaming: false, sendEvents: false, bootstrap: { n: 5 }, fetch: (async () => Response.json({ n: { value: 5, variation: 0, version: 1 } })) as unknown as typeof fetch });
    expect(client.isInitialized).toBe(true);
    expect(client.variation("n", 0)).toBe(5);
    expect(client.variationDetail("n", "x").reason).toEqual({ kind: "ERROR", errorKind: "WRONG_TYPE" });
    await client.close();
  });

  it("ignores a stale identify() response that arrives after a newer one", async () => {
    const delays: Record<string, number> = { a: 0, b: 80, c: 5 };
    const f = (async (url: string) => {
      const ctx = JSON.parse(Buffer.from(new URL(url).searchParams.get("context")!, "base64url").toString()) as { key: string };
      await new Promise((r) => setTimeout(r, delays[ctx.key]));
      return Response.json({ plan: { value: `flags-for-${ctx.key}`, variation: 0, version: 1 } });
    }) as unknown as typeof fetch;
    const client = createClient("cs", { key: "a" }, { baseUrl: "https://x", streaming: false, sendEvents: false, fetch: f });
    await client.waitForInitialization();
    const slow = client.identify({ key: "b" });
    const fast = client.identify({ key: "c" });
    await Promise.all([slow, fast]);
    expect((client.getContext() as { key: string }).key).toBe("c");
    expect(client.variation("plan", "")).toBe("flags-for-c");
    await client.close();
  });

  it("restarts the stream as soon as identify() is called", async () => {
    const s = streamingFetch();
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", fetch: s.f, sendEvents: false });
    await tick();
    void client.identify({ key: "u2" }).catch(() => undefined); // its /flags response (a fake stream) never ends
    await tick();
    const streams = s.requests.filter((u) => u.includes("/stream?"));
    expect(streams).toHaveLength(2);
    expect(JSON.parse(Buffer.from(new URL(streams[1]!).searchParams.get("context")!, "base64url").toString())).toEqual({ key: "u2" });
    await client.close();
  });

  it("close() removes its visibilitychange listener", async () => {
    const listeners = new Set<() => void>();
    const g = globalThis as { document?: unknown };
    g.document = { visibilityState: "visible", addEventListener: (_t: string, fn: () => void) => listeners.add(fn), removeEventListener: (_t: string, fn: () => void) => listeners.delete(fn) };
    try {
      const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", streaming: false, bootstrap: {}, fetch: (async () => Response.json({})) as unknown as typeof fetch });
      expect(listeners.size).toBe(1);
      await client.close();
      expect(listeners.size).toBe(0);
    } finally {
      delete g.document;
    }
  });

  it("offline mode never touches the network", async () => {
    const requests: string[] = [];
    const f = (async (url: string) => {
      requests.push(url);
      return Response.json({});
    }) as unknown as typeof fetch;
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", offline: true, bootstrap: { a: true }, fetch: f });
    expect(client.isInitialized).toBe(true);
    expect(client.variation("a", false)).toBe(true);
    client.track("clicked");
    expect(await client.identify({ key: "u2" })).toEqual({ a: true });
    expect((client.getContext() as { key: string }).key).toBe("u2");
    await client.flush();
    await client.close();
    await tick();
    expect(requests).toEqual([]);
    // Without bootstrap an offline client serves defaults and isn't ready.
    const empty = createClient("cid", { key: "u1" }, { baseUrl: "https://x", offline: true, fetch: f });
    expect(empty.isInitialized).toBe(false);
    expect(empty.variationDetail("a", false).reason).toEqual({ kind: "ERROR", errorKind: "CLIENT_NOT_READY" });
    expect(requests).toEqual([]);
  });

  it("emits stale when the stream drops after loading, and recovered when it reconnects", async () => {
    let n = 0;
    const encoder = new TextEncoder();
    const f = (async () => {
      n++;
      const chunks = ['event: put\ndata: {"a":{"value":1,"variation":0,"version":1}}\n\n'];
      return new Response(new ReadableStream<Uint8Array>({ start: (c) => { for (const ch of chunks) c.enqueue(encoder.encode(ch)); if (n === 1) c.close(); } }));
    }) as unknown as typeof fetch;
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", fetch: f, sendEvents: false });
    const seen: string[] = [];
    client.on("stale", () => seen.push("stale"));
    client.on("recovered", () => seen.push("recovered"));
    await client.waitForInitialization({ timeoutMs: 1000 });
    await new Promise((r) => setTimeout(r, 1200));
    expect(seen).toEqual(["stale", "recovered"]);
    expect(client.isClosed).toBe(false);
    await client.close();
    expect(client.isClosed).toBe(true);
  });

  it("a delete leaves a tombstone: an older patch can't resurrect the flag; malformed patches are ignored", async () => {
    const s = streamingFetch();
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", fetch: s.f, sendEvents: false });
    await tick();
    s.push('event: put\ndata: {"a":{"value":true,"variation":0,"version":1}}\n\n');
    await client.waitForInitialization({ timeoutMs: 1000 });
    s.push('event: delete\ndata: {"key":"a","version":5}\n\n');
    s.push('event: patch\ndata: {"key":"a","value":true,"variation":0,"version":4}\n\n');
    // A delete for a flag we never had still blocks its older patches.
    s.push('event: delete\ndata: {"key":"b","version":3}\n\n');
    s.push('event: patch\ndata: {"key":"b","value":true,"variation":0,"version":2}\n\n');
    // No key / no version: ignored rather than stored under "undefined" or bypassing ordering.
    s.push('event: patch\ndata: {"value":true,"variation":0,"version":9}\n\n');
    s.push('event: patch\ndata: {"key":"c","value":true,"variation":0}\n\n');
    await tick();
    expect(client.allFlags()).toEqual({});
    s.push('event: patch\ndata: {"key":"a","value":false,"variation":1,"version":6}\n\n');
    await tick();
    expect(client.allFlags()).toEqual({ a: false });
    await client.close();
  });

  it("reports a change for a flag keyed __proto__ and doesn't keep empty listener sets", async () => {
    const s = streamingFetch();
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", fetch: s.f, sendEvents: false });
    await tick();
    const changes: string[][] = [];
    client.on("change", (c) => changes.push(Object.keys(c as object)));
    s.push('event: put\ndata: {"__proto__":{"value":1,"variation":0,"version":1}}\n\n');
    await client.waitForInitialization({ timeoutMs: 1000 });
    expect(changes).toEqual([["__proto__"]]);
    expect(client.variation("__proto__", 0)).toBe(1);
    const listeners = (client as unknown as { listeners: Map<string, Set<unknown>> }).listeners;
    const off = client.on("change:x", () => undefined);
    expect(listeners.has("change:x")).toBe(true);
    off();
    expect(listeners.has("change:x")).toBe(false);
    await client.close();
  });

  it("passes an abort signal to the flags request so a stalled server can't hang identify()", async () => {
    const signals: (AbortSignal | undefined)[] = [];
    const f = (async (_url: string, init?: RequestInit) => {
      signals.push(init?.signal ?? undefined);
      return Response.json({});
    }) as unknown as typeof fetch;
    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", streaming: false, sendEvents: false, fetch: f });
    await client.waitForInitialization({ timeoutMs: 1000 });
    expect(signals[0] instanceof AbortSignal).toBe(true);
    await client.close();
  });

  it("exposes one version constant", () => {
    expect(SDK_VERSION).toBe(VERSION_CONSTANT);
    expect(SDK_VERSION).toBe("0.4.0");
  });
});
