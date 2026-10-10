import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { createClient } from "../src/flags/client.js";

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
    const client = createClient("cid", { key: "u1" }, { baseUrl: "http://x/", fetch: s.f, sendEvents: false });
    await tick();
    expect(s.requests[0]).toMatch(/^http:\/\/x\/sdk\/v1\/client\/cid\/stream\?context=/);
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
    const client = createClient("cid", { key: "u1" }, { baseUrl: "http://x", streaming: false, sendEvents: false, bootstrap: { n: 5 }, fetch: (async () => Response.json({ n: { value: 5, variation: 0, version: 1 } })) as unknown as typeof fetch });
    expect(client.isInitialized).toBe(true);
    expect(client.variation("n", 0)).toBe(5);
    expect(client.variationDetail("n", "x").reason).toEqual({ kind: "ERROR", errorKind: "WRONG_TYPE" });
    await client.close();
  });
});
