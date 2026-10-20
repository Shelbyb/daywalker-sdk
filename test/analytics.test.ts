import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { VERSION, createAnalytics, uuidv7 } from "../src/analytics/index.js";
import { SDK_VERSION } from "../src/flags/common/version.js";

type Batch = { event: string; distinct_id: string; properties: Record<string, unknown>; $set?: Record<string, unknown> };

function fakeFetch(statuses: number[] = []) {
  const calls: { url: string; body: { api_key: string; batch: { event: string; distinct_id: string; properties: Record<string, unknown>; $set?: Record<string, unknown> }[] } }[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, body: JSON.parse(String(init.body)) });
    return new Response(null, { status: statuses.shift() ?? 200 });
  }) as unknown as typeof globalThis.fetch;
  return { fetch, calls };
}

describe("analytics", () => {
  it("batches events to /a/batch with the write key", async () => {
    const f = fakeFetch();
    const a = createAnalytics({ writeKey: "dpa_test", host: "https://dp.example.com/", fetch: f.fetch });
    a.capture("signed_up", { plan: "pro" });
    a.capture("project_created");
    await a.flush();
    expect(f.calls).toHaveLength(1);
    expect(f.calls[0]!.url).toBe("https://dp.example.com/a/batch");
    expect(f.calls[0]!.body.api_key).toBe("dpa_test");
    expect(f.calls[0]!.body.batch.map((e) => e.event)).toEqual(["signed_up", "project_created"]);
    expect(f.calls[0]!.body.batch[0]!.properties).toMatchObject({ plan: "pro", $lib: "devpulse-analytics" });
    expect(f.calls[0]!.body.batch[0]!.properties.$session_id).toBe(f.calls[0]!.body.batch[1]!.properties.$session_id);
  });

  it("identify sends $identify with the anonymous id and switches distinct id", async () => {
    const f = fakeFetch();
    const a = createAnalytics({ writeKey: "dpa_test", host: "https://dp", fetch: f.fetch });
    const anon = a.getDistinctId();
    a.identify("user-1", { email: "a@b.c" });
    a.capture("x");
    await a.flush();
    const [id, x] = f.calls[0]!.body.batch as [Batch, Batch];
    expect(id).toMatchObject({ event: "$identify", distinct_id: "user-1", $set: { email: "a@b.c" } });
    expect(id.properties.$anon_distinct_id).toBe(anon);
    expect(x.distinct_id).toBe("user-1");
    a.reset();
    expect(a.getDistinctId()).not.toBe("user-1");
  });

  it("server-side capture with distinctId, super properties and flags", async () => {
    const f = fakeFetch();
    const a = createAnalytics({ writeKey: "dpa_test", host: "https://dp", fetch: f.fetch, flags: { allFlags: () => ({ "new-checkout": true }) } });
    a.register({ app: "api" });
    a.capture("invoice_paid", { amount: 5 }, { distinctId: "cust-9" });
    await a.flush();
    const e = f.calls[0]!.body.batch[0]!;
    expect(e.distinct_id).toBe("cust-9");
    expect(e.properties).toMatchObject({ app: "api", amount: 5, "$feature/new-checkout": true });
    expect(e.properties.$session_id).toBeUndefined();
  });

  it("requeues on 5xx and drops on 400", async () => {
    const f = fakeFetch([503, 200]);
    const a = createAnalytics({ writeKey: "dpa_test", host: "https://dp", fetch: f.fetch });
    a.capture("x");
    await a.flush();
    expect(f.calls).toHaveLength(1);
    await new Promise((r) => setTimeout(r, 2100));
    await a.flush();
    expect(f.calls).toHaveLength(2);
    expect(f.calls[1]!.body.batch[0]!.event).toBe("x");
    const g = fakeFetch([400]);
    const b = createAnalytics({ writeKey: "dpa_test", host: "https://dp", fetch: g.fetch });
    b.capture("bad");
    await b.flush();
    await b.flush();
    expect(g.calls).toHaveLength(1);
  });

  it("opt-out stops capture", async () => {
    const f = fakeFetch();
    const a = createAnalytics({ writeKey: "dpa_test", host: "https://dp", fetch: f.fetch, optedOut: true });
    a.capture("x");
    await a.flush();
    expect(f.calls).toHaveLength(0);
    a.optIn();
    a.capture("y");
    await a.flush();
    expect(f.calls).toHaveLength(1);
  });

  it("uuidv7 is time-ordered and versioned", () => {
    const a = uuidv7(1_700_000_000_000);
    const b = uuidv7(1_700_000_000_001);
    expect(a < b).toBe(true);
    expect(a[14]).toBe("7");
    expect(a.slice(0, 8)).toBe("018bcfe5");
  });

  it("drops an in-flight batch that fails after optOut() instead of retrying it", async () => {
    let call = 0;
    const sent: string[] = [];
    let release!: () => void;
    const fetch = (async (_u: string, init: RequestInit) => {
      call++;
      if (call === 1) {
        await new Promise<void>((r) => (release = r));
        throw new TypeError("offline");
      }
      sent.push(...(JSON.parse(String(init.body)) as { batch: { event: string }[] }).batch.map((e) => e.event));
      return Response.json({ status: 1 });
    }) as unknown as typeof globalThis.fetch;
    const a = createAnalytics({ writeKey: "dpa_x", host: "https://dp", fetch, flushAt: 1 });
    a.capture("viewed_pricing"); // in flight
    a.optOut();
    release();
    await new Promise((r) => setTimeout(r, 20));
    await a.flush();
    a.optIn();
    await a.flush();
    expect(sent).toEqual([]);
    await a.shutdown();
  });

  it("reports the package version", async () => {
    expect(VERSION).toBe(SDK_VERSION);
    const f = fakeFetch();
    const a = createAnalytics({ writeKey: "dpa_test", host: "https://dp", fetch: f.fetch });
    a.capture("x");
    await a.flush();
    expect(f.calls[0]!.body.batch[0]!.properties.$lib_version).toBe("0.4.0");
  });
});

describe("analytics in a browser", () => {
  type Sent = { body: string; keepalive?: boolean };
  /** Fake just enough of a browser, then load a fresh copy of the module (it detects browsers at load). */
  async function browser(href: string, beaconOk = true) {
    const beacons: string[] = [];
    const listeners: Record<string, (() => void)[]> = {};
    const on = (t: string, fn: () => void) => void (listeners[t] ??= []).push(fn);
    const u = new URL(href);
    const g = globalThis as Record<string, unknown>;
    const saved = Object.fromEntries(["window", "document", "location", "history", "screen", "navigator"].map((k) => [k, Object.getOwnPropertyDescriptor(g, k)]));
    const def = (k: string, v: unknown) => Object.defineProperty(g, k, { value: v, configurable: true, writable: true });
    def("window", { addEventListener: on, removeEventListener() {}, innerWidth: 1, innerHeight: 1 });
    def("document", { addEventListener: on, removeEventListener() {}, referrer: "https://app.example.com/reset/tok_secret?x=1", title: "t", visibilityState: "visible" });
    def("location", { href: u.href, host: u.host, pathname: u.pathname, search: u.search });
    def("history", { pushState() {}, replaceState() {} });
    def("screen", { width: 1, height: 1 });
    def("navigator", { language: "en", sendBeacon: (_u: string, blob: Blob) => (blob.text().then((t) => beacons.push(t)), beaconOk) });
    const mod = (await import(`../src/analytics/index.js?browser=${Math.random()}`)) as typeof import("../src/analytics/index.js");
    const restore = () => {
      for (const [k, d] of Object.entries(saved)) {
        if (d) Object.defineProperty(g, k, d);
        else delete g[k];
      }
    };
    return { mod, beacons, fire: (t: string) => listeners[t]?.forEach((fn) => fn()), restore };
  }

  it("uses keepalive only for bodies under 60 KB, and beacons in chunks under 60 KB", async () => {
    const b = await browser("https://app.example.com/home");
    try {
      const sent: Sent[] = [];
      const fetch = (async (_u: string, init: RequestInit) => {
        sent.push({ body: String(init.body), keepalive: init.keepalive });
        return Response.json({});
      }) as unknown as typeof globalThis.fetch;
      const a = b.mod.createAnalytics({ writeKey: "dpa_b", host: "https://dp", fetch, persistence: "memory", autocapturePageviews: false, flushAt: 1000 });
      a.capture("small");
      await a.flush();
      for (let i = 0; i < 20; i++) a.capture("big", { blob: "x".repeat(5000) });
      await a.flush();
      expect(sent.map((s) => s.keepalive)).toEqual([true, false]);
      expect(Buffer.byteLength(sent[1]!.body)).toBeGreaterThan(60_000);
      // Page hide: beacons, each under the 64 KiB budget, covering every queued event.
      for (let i = 0; i < 30; i++) a.capture("big", { blob: "y".repeat(5000) });
      b.fire("pagehide");
      await new Promise((r) => setTimeout(r, 10));
      expect(b.beacons.length).toBeGreaterThan(1);
      for (const body of b.beacons) expect(Buffer.byteLength(body)).toBeLessThan(60_000);
      expect(b.beacons.flatMap((body) => (JSON.parse(body) as { batch: unknown[] }).batch)).toHaveLength(30);
      await a.shutdown();
    } finally {
      b.restore();
    }
  });

  it("keeps events queued when the beacon is refused", async () => {
    const b = await browser("https://app.example.com/home", false);
    try {
      const f = fakeFetch();
      const a = b.mod.createAnalytics({ writeKey: "dpa_b2", host: "https://dp", fetch: f.fetch, persistence: "memory", autocapturePageviews: false, flushAt: 1000 });
      a.capture("x");
      b.fire("pagehide");
      await a.flush();
      expect(f.calls[0]!.body.batch.map((e) => e.event)).toEqual(["x"]);
      await a.shutdown();
    } finally {
      b.restore();
    }
  });

  it("applies sanitizePath to every path and URL it sends", async () => {
    const b = await browser("https://app.example.com/reset/tok_secret?utm_source=mail&code=1#frag");
    try {
      const f = fakeFetch();
      const a = b.mod.createAnalytics({ writeKey: "dpa_b3", host: "https://dp", fetch: f.fetch, persistence: "memory", sanitizePath: (p) => p.replace(/^\/reset\/[^/]+/, "/reset/:token") });
      await a.flush();
      const pv = f.calls[0]!.body.batch[0]! as { event: string; properties: Record<string, unknown>; $set_once?: Record<string, unknown> };
      expect(pv.event).toBe("$pageview");
      expect(pv.properties.$pathname).toBe("/reset/:token");
      expect(pv.properties.$current_url).toBe("https://app.example.com/reset/:token?utm_source=mail");
      expect(pv.properties.$referrer).toBe("https://app.example.com/reset/:token");
      expect(pv.$set_once).toMatchObject({ $initial_pathname: "/reset/:token", $initial_current_url: "https://app.example.com/reset/:token?utm_source=mail" });
      expect(JSON.stringify(f.calls)).not.toMatch(/tok_secret/);
      await a.shutdown();
    } finally {
      b.restore();
    }
  });

  it("ignores a corrupted persisted state instead of throwing", async () => {
    const b = await browser("https://app.example.com/");
    const g = globalThis as Record<string, unknown>;
    const saved = Object.getOwnPropertyDescriptor(g, "localStorage");
    const data: Record<string, string> = { dp_analytics_dpa_c1: '"oops"', dp_analytics_dpa_c2: "[1]", dp_analytics_dpa_c3: '{"distinctId":"kept","identified":false,"props":{}}' };
    Object.defineProperty(g, "localStorage", { value: { getItem: (k: string) => data[k] ?? null, setItem: (k: string, v: string) => void (data[k] = v) }, configurable: true, writable: true });
    try {
      const f = fakeFetch();
      for (const key of ["dpa_c1", "dpa_c2"]) {
        const a = b.mod.createAnalytics({ writeKey: key, host: "https://dp", fetch: f.fetch, autocapturePageviews: false });
        expect(a.getDistinctId()).toMatch(/^[0-9a-f-]{36}$/);
        await a.shutdown();
      }
      const kept = b.mod.createAnalytics({ writeKey: "dpa_c3", host: "https://dp", fetch: f.fetch, autocapturePageviews: false });
      expect(kept.getDistinctId()).toBe("kept");
      await kept.shutdown();
    } finally {
      if (saved) Object.defineProperty(g, "localStorage", saved);
      else delete g.localStorage;
      b.restore();
    }
  });
});

describe("analytics hardening", () => {
  it("times out a hung request, requeues it and keeps flush() from hanging", async () => {
    let calls = 0;
    const fetch = ((_u: string, init: RequestInit) => {
      calls++;
      return new Promise((_r, reject) => init.signal!.addEventListener("abort", () => reject(init.signal!.reason)));
    }) as unknown as typeof globalThis.fetch;
    const errors: Error[] = [];
    const a = createAnalytics({ writeKey: "dpa_t", host: "https://dp", fetch, timeoutMs: 20, onError: (e) => errors.push(e) });
    a.capture("x");
    await a.flush();
    expect(calls).toBe(1);
    expect(errors[0]!.name).toBe("TimeoutError");
    const f = fakeFetch();
    const b = createAnalytics({ writeKey: "dpa_t", host: "https://dp", fetch: f.fetch, timeoutMs: 0 });
    b.capture("y");
    await b.flush();
    expect(f.calls).toHaveLength(1);
  });

  it("re-applies maxQueueSize when a failed batch is requeued", async () => {
    let release: ((r: Response) => void) | undefined;
    let n = 0;
    const fetch = (() => (n++ ? Promise.resolve(new Response(null, { status: 200 })) : new Promise<Response>((r) => (release = r)))) as unknown as typeof globalThis.fetch;
    const a = createAnalytics({ writeKey: "dpa_t", host: "https://dp", fetch, maxQueueSize: 5, flushAt: 1000 });
    for (let i = 0; i < 5; i++) a.capture(`old${i}`);
    const p = a.flush();
    await new Promise((r) => setTimeout(r, 0));
    for (let i = 0; i < 5; i++) a.capture(`new${i}`);
    release!(new Response(null, { status: 503 }));
    await p;
    const queue = (a as unknown as { queue: { event: string }[] }).queue;
    expect(queue.map((e) => e.event)).toEqual(["new0", "new1", "new2", "new3", "new4"]);
    await a.shutdown();
    expect(n).toBe(2);
  });
});
