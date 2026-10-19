import { afterEach, describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { createAnalytics } from "../src/analytics/index.js";
import { privacySignalOn, startWebVitals, type WebVitalsContext, type WebVitalsPayload } from "../src/analytics/web-vitals.js";

type Cb = (list: { getEntries(): unknown[] }) => void;
type Listener = (ev: unknown) => void;

class FakePO {
  static supported: string[] | undefined = ["paint", "largest-contentful-paint", "layout-shift", "event", "first-input"];
  static all: FakePO[] = [];
  static throwOn: string | undefined;
  type = "";
  pending: unknown[] = [];
  disconnected = false;
  static supportedEntryTypes = FakePO.supported;
  constructor(public cb: Cb) {
    FakePO.all.push(this);
  }
  observe(cfg: { type: string; buffered?: boolean; durationThreshold?: number }) {
    if (FakePO.throwOn === cfg.type) throw new Error("nope");
    this.type = cfg.type;
    this.cfg = cfg;
  }
  cfg: unknown;
  disconnect() {
    this.disconnected = true;
  }
  takeRecords() {
    const r = this.pending;
    this.pending = [];
    return r;
  }
  emit(...entries: unknown[]) {
    this.cb({ getEntries: () => entries });
  }
}
const po = (type: string) => FakePO.all.find((o) => o.type === type)!;

const KEYS = ["window", "document", "location", "navigator", "performance", "PerformanceObserver", "crypto"] as const;

type Env = ReturnType<typeof setup>;
function setup(opts: { nav?: Record<string, unknown>; navEntry?: Record<string, unknown> | null; visibility?: string; prerendering?: boolean; wasDiscarded?: boolean; beacon?: "ok" | "refuse" | "throw" | "missing"; winExtra?: Record<string, unknown>; supported?: string[] | undefined; noEntries?: boolean } = {}) {
  FakePO.all = [];
  FakePO.throwOn = undefined;
  FakePO.supportedEntryTypes = "supported" in opts ? (opts.supported as string[]) : ["paint", "largest-contentful-paint", "layout-shift", "event", "first-input"];
  const listeners: Record<string, Listener[]> = {};
  const removed: string[] = [];
  const on = (t: string, fn: Listener) => void (listeners[t] ??= []).push(fn);
  const off = (t: string) => void removed.push(t);
  const beacons: { url: string; body: unknown }[] = [];
  const beacon = opts.beacon ?? "ok";
  const nav: Record<string, unknown> = { userAgent: "x", maxTouchPoints: 0, ...opts.nav };
  if (beacon !== "missing") {
    nav.sendBeacon = (url: string, body: unknown) => {
      if (beacon === "throw") throw new Error("boom");
      beacons.push({ url, body });
      return beacon === "ok";
    };
  }
  const doc: Record<string, unknown> = { addEventListener: on, removeEventListener: off, visibilityState: opts.visibility ?? "visible", prerendering: opts.prerendering, wasDiscarded: opts.wasDiscarded };
  const perf = {
    now: () => 4242,
    interactionCount: 0,
    getEntriesByType: opts.noEntries ? undefined : () => (opts.navEntry === null ? [] : [{ type: "back_forward", responseStart: 120.44, loadEventEnd: 900.06, activationStart: 0, ...opts.navEntry }]),
  };
  const saved = Object.fromEntries(KEYS.map((k) => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  const def = (k: string, v: unknown) => Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  def("window", { addEventListener: on, removeEventListener: off, ...opts.winExtra });
  def("document", doc);
  def("location", { pathname: "/users/42/orders", search: "?token=secret", hash: "#x" });
  def("navigator", nav);
  def("performance", perf);
  def("PerformanceObserver", FakePO);
  def("crypto", { randomUUID: () => `id-${++idCounter}` });
  const restore = () => {
    for (const [k, d] of Object.entries(saved)) {
      if (d) Object.defineProperty(globalThis, k, d);
      else delete (globalThis as Record<string, unknown>)[k];
    }
  };
  return {
    doc,
    nav,
    perf,
    beacons,
    removed,
    listeners,
    restore,
    fire: (t: string, ev: unknown = {}) => listeners[t]?.forEach((fn) => fn(ev)),
    hide: () => {
      doc.visibilityState = "hidden";
      for (const fn of listeners.visibilitychange ?? []) fn({});
    },
    sent: () => beacons.map((b) => JSON.parse(String(b.body)) as WebVitalsPayload),
  };
}
let idCounter = 0;
let env: Env | undefined;
afterEach(() => {
  env?.restore();
  env = undefined;
});

const ctx = (over: Partial<WebVitalsContext> = {}): WebVitalsContext => ({ writeKey: "dpa_k", endpoint: "https://dp.example.com/a/rum", isOptedOut: () => false, sanitizePath: (p) => p, ...over });
const names = (p: WebVitalsPayload) => p.events.map((e) => e.name).sort();
const val = (p: WebVitalsPayload, n: string) => p.events.find((e) => e.name === n)?.value;

describe("web vitals: measuring", () => {
  it("sends every metric once with the contract's field names, as text via sendBeacon", () => {
    env = setup();
    startWebVitals(ctx({ }), { release: "1.4.2", environment: "production" });
    po("paint").emit({ name: "first-paint", startTime: 10 }, { name: "first-contentful-paint", startTime: 321.26 });
    po("largest-contentful-paint").emit({ startTime: 500 }, { startTime: 2140.54, element: { nodeType: 1, localName: "img", id: "", className: "hero big extra", parentElement: { nodeType: 1, localName: "main", id: "root", className: "", parentElement: null } } });
    env.hide();
    expect(env.beacons).toHaveLength(1);
    expect(env.beacons[0]!.url).toBe("https://dp.example.com/a/rum");
    expect(typeof env.beacons[0]!.body).toBe("string");
    const p = env.sent()[0]!;
    expect(p).toMatchObject({ key: "dpa_k", pageId: "id-" + idCounter, navigationType: "back-forward", path: "/users/42/orders", release: "1.4.2", environment: "production" });
    expect(Object.keys(p).sort()).toEqual(["environment", "events", "key", "navigationType", "pageId", "path", "release"]);
    expect(names(p)).toEqual(["CLS", "FCP", "LCP", "LOAD", "TTFB"]);
    expect(val(p, "FCP")).toBe(321.3);
    expect(val(p, "LCP")).toBe(2140.5);
    expect(val(p, "TTFB")).toBe(120.4);
    expect(val(p, "LOAD")).toBe(900.1);
    expect(val(p, "CLS")).toBe(0);
    expect(p.events.find((e) => e.name === "LCP")!.selector).toBe("main#root>img.hero.big");
    expect(JSON.stringify(p)).not.toMatch(/secret|#x/);
  });

  it("sums CLS in session windows, ignores recent-input shifts and re-sends only when it grows", () => {
    env = setup();
    startWebVitals(ctx());
    const node = (name: string) => ({ nodeType: 1, localName: name, id: "", className: "", parentElement: null });
    const ls = po("layout-shift");
    ls.emit(
      { startTime: 100, value: 0.05, sources: [{ node: { nodeType: 3, parentElement: node("p") } }] },
      { startTime: 200, value: 0.1, hadRecentInput: true },
      { startTime: 600, value: 0.07, sources: [{ node: node("section") }, { node: node("aside") }] },
      { startTime: 700, value: 0.01 },
    );
    // new window (gap >= 1 s) that is smaller than the first
    ls.emit({ startTime: 5000, value: 0.02, sources: [] });
    env.hide();
    expect(val(env.sent()[0]!, "CLS")).toBe(0.13);
    expect(env.sent()[0]!.events.find((e) => e.name === "CLS")!.selector).toBe("section");
    env.hide();
    expect(env.beacons).toHaveLength(1);
    // a longer burst (5 s cap) then a bigger window
    ls.emit({ startTime: 9000, value: 0.2 }, { startTime: 9500, value: 0.1 }, { startTime: 15000, value: 0.01 });
    env.hide();
    expect(env.beacons).toHaveLength(2);
    expect(env.sent()[1]!.events.map((e) => [e.name, e.value])).toEqual([["CLS", 0.3]]);
    expect(env.sent()[1]!.pageId).toBe(env.sent()[0]!.pageId);
  });

  it("reports INP as the slowest interaction, and the 98th percentile for busy pages", () => {
    env = setup();
    startWebVitals(ctx());
    const target = { nodeType: 1, localName: "button", id: "buy", className: "", parentElement: null };
    const ev = po("event");
    ev.emit({ interactionId: 0, duration: 999 }, { interactionId: 1, duration: 80, target }, { interactionId: 2, duration: 240, target: { ...target, id: "", className: "a" } });
    ev.emit({ interactionId: 2, duration: 100 }, { interactionId: 1, duration: 120, target: undefined });
    po("first-input").emit({ interactionId: 3, duration: 56 });
    env.hide();
    const inp = env.sent()[0]!.events.find((e) => e.name === "INP")!;
    expect(inp).toMatchObject({ value: 240, selector: "button.a" });
    expect((ev.cfg as { durationThreshold: number }).durationThreshold).toBe(40);

    // 12 interactions kept to the 10 slowest; with interactionCount 100 the 3rd slowest (390) is the p98 pick
    (env.perf as { interactionCount: number }).interactionCount = 100;
    ev.emit(...Array.from({ length: 12 }, (_, i) => ({ interactionId: 10 + i, duration: 300 + i * 10, target })));
    env.hide();
    expect(val(env.sent()[1]!, "INP")).toBe(390);
  });

  it("skips paint metrics for pages that started hidden, and LCP/FCP after the page was hidden", () => {
    env = setup({ visibility: "hidden" });
    startWebVitals(ctx());
    po("paint").emit({ name: "first-contentful-paint", startTime: 5 });
    po("largest-contentful-paint").emit({ startTime: 5 });
    env.fire("pagehide");
    expect(names(env.sent()[0]!)).toEqual(["CLS", "LOAD", "TTFB"]);

    env.restore();
    env = setup();
    startWebVitals(ctx());
    env.hide();
    po("paint").emit({ name: "first-contentful-paint", startTime: 9000 });
    env.hide();
    expect(env.sent().flatMap(names).includes("FCP")).toBe(false);
    // a second hide keeps the first hidden time
    po("paint").emit({ name: "first-contentful-paint", startTime: 100 });
    env.hide();
    expect(env.sent().flatMap(names).includes("FCP")).toBe(true);
  });

  it("flushes records still pending in the observers and ignores visible visibilitychange", () => {
    env = setup();
    startWebVitals(ctx());
    po("paint").pending.push({ name: "first-contentful-paint", startTime: 77 });
    env.doc.visibilityState = "visible";
    env.fire("visibilitychange");
    expect(env.beacons).toHaveLength(0);
    env.fire("pagehide");
    expect(val(env.sent()[0]!, "FCP")).toBe(77);
  });

  it("subtracts activationStart and reports prerender, discarded and reload navigation types", () => {
    env = setup({ navEntry: { activationStart: 100, type: "navigate" } });
    startWebVitals(ctx());
    po("paint").emit({ name: "first-contentful-paint", startTime: 150 }, );
    po("largest-contentful-paint").emit({ startTime: 50 });
    env.fire("pagehide");
    const p = env.sent()[0]!;
    expect(p.navigationType).toBe("prerender");
    expect(val(p, "FCP")).toBe(50);
    expect(val(p, "LCP")).toBe(0);
    expect(val(p, "TTFB")).toBe(20.4);
    env.restore();

    env = setup({ prerendering: true, navEntry: { type: "navigate" } });
    startWebVitals(ctx());
    env.fire("pagehide");
    expect(env.sent()[0]!.navigationType).toBe("prerender");
    env.restore();

    env = setup({ wasDiscarded: true });
    startWebVitals(ctx());
    env.fire("pagehide");
    expect(env.sent()[0]!.navigationType).toBe("restore");
    env.restore();

    env = setup({ navEntry: { type: "reload" } });
    startWebVitals(ctx());
    env.fire("pagehide");
    expect(env.sent()[0]!.navigationType).toBe("reload");
    env.restore();

    env = setup({ navEntry: null });
    startWebVitals(ctx());
    env.fire("pagehide");
    expect(env.sent()[0]!.navigationType).toBe("navigate");
    expect(names(env.sent()[0]!)).toEqual(["CLS"]);
    env.restore();

    env = setup({ noEntries: true });
    startWebVitals(ctx());
    env.fire("pagehide");
    expect(env.sent()[0]!.navigationType).toBe("navigate");
  });

  it("skips TTFB and LOAD until navigation timing has them, then sends them once", () => {
    env = setup({ navEntry: { responseStart: 0, loadEventEnd: 0 } });
    startWebVitals(ctx());
    env.hide();
    expect(names(env.sent()[0]!)).toEqual(["CLS"]);
    (env.perf as { getEntriesByType: () => unknown[] }).getEntriesByType = () => [{ type: "navigate", responseStart: 10, loadEventEnd: 20 }];
    env.hide();
    env.hide();
    expect(env.beacons).toHaveLength(2);
    expect(names(env.sent()[1]!)).toEqual(["LOAD", "TTFB"]);
  });

  it("starts a new page view after a back/forward cache restore", () => {
    env = setup();
    startWebVitals(ctx());
    po("layout-shift").emit({ startTime: 1, value: 0.2 });
    env.hide();
    const first = env.sent()[0]!;
    env.fire("pageshow", { persisted: false });
    env.hide();
    expect(env.beacons).toHaveLength(1);
    env.fire("pageshow", { persisted: true });
    po("layout-shift").emit({ startTime: 1, value: 0.05 });
    env.hide();
    const second = env.sent()[1]!;
    expect(second.pageId).not.toBe(first.pageId);
    expect(second.navigationType).toBe("back-forward-cache");
    expect(val(second, "CLS")).toBe(0.05);
  });

  it("survives unsupported or throwing entry types", () => {
    env = setup({ supported: ["paint"] });
    startWebVitals(ctx());
    expect(FakePO.all.map((o) => o.type)).toEqual(["paint"]);
    env.hide();
    // no layout-shift support: CLS is not reported as 0
    expect(names(env.sent()[0]!)).toEqual(["LOAD", "TTFB"]);
    env.restore();

    env = setup({ supported: undefined });
    FakePO.throwOn = "event";
    startWebVitals(ctx());
    expect(FakePO.all.map((o) => o.type).includes("event")).toBe(false);
    expect(FakePO.all.map((o) => o.type).includes("first-input")).toBe(true);
  });
});

describe("web vitals: payload fields", () => {
  it("adds connection and tablet hints, validates release/environment, sanitizes the path", () => {
    env = setup({ nav: { connection: { effectiveType: "3g" }, maxTouchPoints: 5, userAgent: "Macintosh" } });
    startWebVitals(ctx({ sanitizePath: (p) => p.replace(/\d+/, ":id") }), { release: "bad release!", environment: "x".repeat(65) });
    env.fire("pagehide");
    const p = env.sent()[0]!;
    expect(p).toMatchObject({ connection: "3g", device: "tablet", path: "/users/:id/orders" });
    expect(p.release).toBeUndefined();
    expect(p.environment).toBeUndefined();
    env.restore();

    env = setup({ nav: { connection: { effectiveType: "5g" } } });
    startWebVitals(ctx(), { release: "r".repeat(101), path: "/users/:id" });
    env.fire("pagehide");
    expect(env.sent()[0]!.connection).toBeUndefined();
    expect(env.sent()[0]!.device).toBeUndefined();
    expect(env.sent()[0]!.release).toBeUndefined();
    expect(env.sent()[0]!.path).toBe("/users/:id");
  });

  it("keeps payloads within the server limits", () => {
    env = setup();
    startWebVitals(ctx(), { path: "/" + "p".repeat(3000) });
    const sel = { nodeType: 1, localName: "div", id: "i".repeat(300), className: "", parentElement: null };
    po("largest-contentful-paint").emit({ startTime: 1, element: sel });
    env.hide();
    const p = env.sent()[0]!;
    expect(p.path.length).toBe(2048);
    expect(p.events.length).toBeLessThan(200);
    expect(p.events.find((e) => e.name === "LCP")!.selector!.length).toBe(200);
    expect(p.pageId).toMatch(/^[\w.:-]{1,64}$/);
    expect(Buffer.byteLength(String(env.beacons[0]!.body))).toBeLessThan(64 * 1024);
    for (const e of p.events) expect(e.value >= 0 && e.value <= 600_000).toBe(true);
  });

  it("falls back to a generated page id without crypto.randomUUID, and to / when sanitizePath throws", () => {
    env = setup();
    Object.defineProperty(globalThis, "crypto", { value: {}, configurable: true, writable: true });
    const errors: Error[] = [];
    startWebVitals(ctx({ sanitizePath: () => { throw new Error("bad"); }, onError: (e) => errors.push(e) }));
    env.fire("pagehide");
    expect(env.sent()[0]!.pageId).toMatch(/^[\w.:-]+$/);
    expect(env.sent()[0]!.path).toBe("/");
    expect(errors).toHaveLength(1);
  });

  it("uses / when there is no location", () => {
    env = setup();
    Object.defineProperty(globalThis, "location", { value: undefined, configurable: true, writable: true });
    startWebVitals(ctx());
    env.fire("pagehide");
    expect(env.sent()[0]!.path).toBe("/");
  });
});

describe("web vitals: delivery", () => {
  const fetchSpy = () => {
    const calls: { url: string; init: RequestInit }[] = [];
    const fetch = (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(null, { status: 202 });
    }) as unknown as typeof globalThis.fetch;
    return { calls, fetch };
  };

  for (const beacon of ["refuse", "throw", "missing"] as const) {
    it(`falls back to fetch keepalive when sendBeacon is ${beacon}`, () => {
      env = setup({ beacon });
      const f = fetchSpy();
      startWebVitals(ctx({ fetch: f.fetch }));
      env.hide();
      expect(f.calls).toHaveLength(1);
      expect(f.calls[0]!.url).toBe("https://dp.example.com/a/rum");
      expect(f.calls[0]!.init).toMatchObject({ method: "POST", keepalive: true, credentials: "omit", headers: { "content-type": "text/plain" } });
      expect(JSON.parse(String(f.calls[0]!.init.body)).key).toBe("dpa_k");
    });
  }

  it("reports fetch failures to onError, sync or async, and never throws", async () => {
    env = setup({ beacon: "refuse" });
    const errors: string[] = [];
    startWebVitals(ctx({ fetch: (async () => { throw new Error("offline"); }) as unknown as typeof fetch, onError: (e) => errors.push(e.message) }));
    env.hide();
    await new Promise((r) => setTimeout(r, 5));
    env.restore();
    env = setup({ beacon: "refuse" });
    startWebVitals(ctx({ fetch: ((() => { throw new Error("sync"); }) as unknown) as typeof fetch, onError: (e) => errors.push(e.message) }));
    env.hide();
    env.restore();
    env = setup({ beacon: "refuse" });
    startWebVitals(ctx({ fetch: ((() => { throw new Error("quiet"); }) as unknown) as typeof fetch }));
    env.hide();
    expect(errors).toEqual(["offline", "sync"]);
  });

  it("uses the global fetch when none is configured", () => {
    env = setup({ beacon: "missing" });
    const real = globalThis.fetch;
    const f = fetchSpy();
    globalThis.fetch = f.fetch;
    try {
      startWebVitals(ctx());
      env.hide();
    } finally {
      globalThis.fetch = real;
    }
    expect(f.calls).toHaveLength(1);
  });

  it("does not catch fetch rejections without onError", async () => {
    env = setup({ beacon: "refuse" });
    startWebVitals(ctx({ fetch: (async () => { throw new Error("x"); }) as unknown as typeof fetch }));
    env.hide();
    await new Promise((r) => setTimeout(r, 5));
  });
});

describe("web vitals: privacy, sampling, environment, cleanup", () => {
  it("does nothing outside browsers or without PerformanceObserver", () => {
    expect(() => startWebVitals(ctx())()).not.toThrow();
    env = setup();
    Object.defineProperty(globalThis, "PerformanceObserver", { value: undefined, configurable: true, writable: true });
    const stop = startWebVitals(ctx());
    stop();
    expect(env.listeners.pagehide).toBeUndefined();
    env.restore();
    env = setup();
    Object.defineProperty(globalThis, "performance", { value: undefined, configurable: true, writable: true });
    startWebVitals(ctx())();
    expect(env.listeners.pagehide).toBeUndefined();
  });

  it("is off for Do Not Track and Global Privacy Control", () => {
    for (const nav of [{ doNotTrack: "1" }, { msDoNotTrack: "1" }, { globalPrivacyControl: true }]) {
      env = setup({ nav });
      expect(privacySignalOn()).toBe(true);
      startWebVitals(ctx());
      expect(FakePO.all).toHaveLength(0);
      env.restore();
    }
    env = setup({ winExtra: { doNotTrack: "1" } });
    startWebVitals(ctx());
    expect(FakePO.all).toHaveLength(0);
    env.restore();
    env = setup({ nav: { doNotTrack: "0", globalPrivacyControl: false } });
    expect(privacySignalOn()).toBe(false);
    env.restore();
    expect(privacySignalOn()).toBe(false);
  });

  it("stops sending if DNT turns on later", () => {
    env = setup();
    startWebVitals(ctx());
    env.nav.doNotTrack = "1";
    env.hide();
    expect(env.beacons).toHaveLength(0);
  });

  it("samples per page view", () => {
    const random = Math.random;
    try {
      env = setup();
      Math.random = () => 0.5;
      startWebVitals(ctx(), { sampleRate: 0.5 });
      expect(FakePO.all).toHaveLength(0);
      startWebVitals(ctx(), { sampleRate: 0 });
      expect(FakePO.all).toHaveLength(0);
      startWebVitals(ctx(), { sampleRate: 0.51 });
      expect(FakePO.all.length).toBeGreaterThan(0);
      FakePO.all = [];
      startWebVitals(ctx(), { sampleRate: 7 });
      expect(FakePO.all.length).toBeGreaterThan(0);
      FakePO.all = [];
      startWebVitals(ctx(), { sampleRate: Number.NaN });
      expect(FakePO.all.length).toBeGreaterThan(0);
    } finally {
      Math.random = random;
    }
  });

  it("holds metrics while opted out and sends them after opt-in", () => {
    env = setup();
    let out = true;
    startWebVitals(ctx({ isOptedOut: () => out }));
    env.hide();
    expect(env.beacons).toHaveLength(0);
    out = false;
    env.hide();
    expect(env.beacons).toHaveLength(1);
  });

  it("stop removes listeners and observers, and is idempotent", () => {
    env = setup();
    const stop = startWebVitals(ctx());
    stop();
    stop();
    expect(env.removed.sort()).toEqual(["pagehide", "pageshow", "visibilitychange"]);
    expect(FakePO.all.every((o) => o.disconnected)).toBe(true);
  });
});

describe("analytics.captureWebVitals", () => {
  const fetchNoop = (async () => new Response(null, { status: 200 })) as unknown as typeof fetch;

  it("sends to {host}/a/rum with the write key and the client's sanitizePath, and stops on shutdown", async () => {
    env = setup();
    const a = createAnalytics({ writeKey: "dpa_w", host: "https://dp.example.com/", fetch: fetchNoop, persistence: "memory", sanitizePath: (p) => p.replace(/\d+/, ":id") });
    const stop = a.captureWebVitals({ release: "2.0.0" });
    expect(a.captureWebVitals()).toBe(stop);
    env.hide();
    expect(env.beacons[0]!.url).toBe("https://dp.example.com/a/rum");
    expect(env.sent()[0]).toMatchObject({ key: "dpa_w", path: "/users/:id/orders", release: "2.0.0" });
    await a.shutdown();
    expect(FakePO.all.every((o) => o.disconnected)).toBe(true);
    // after a stop it can be started again
    env.beacons.length = 0;
    const again = a.captureWebVitals();
    expect(again).not.toBe(stop);
    stop();
    await a.shutdown();
  });

  it("respects optOut/optIn and the optedOut option", () => {
    env = setup();
    const a = createAnalytics({ writeKey: "dpa_w", host: "https://dp", fetch: fetchNoop, persistence: "memory", optedOut: true });
    const stop = a.captureWebVitals();
    env.hide();
    expect(env.beacons).toHaveLength(0);
    a.optIn();
    env.hide();
    expect(env.beacons).toHaveLength(1);
    a.optOut();
    po("layout-shift").emit({ startTime: 1, value: 0.9 });
    env.hide();
    expect(env.beacons).toHaveLength(1);
    stop();
  });

  it("starts from the autocaptureWebVitals option (true or options), off by default", async () => {
    env = setup();
    const off = createAnalytics({ writeKey: "dpa_w", host: "https://dp", fetch: fetchNoop, persistence: "memory", autocapturePageviews: false });
    expect(FakePO.all).toHaveLength(0);
    await off.shutdown();
    const on = createAnalytics({ writeKey: "dpa_w", host: "https://dp", fetch: fetchNoop, persistence: "memory", autocapturePageviews: false, autocaptureWebVitals: true });
    expect(FakePO.all.length).toBeGreaterThan(0);
    await on.shutdown();
    FakePO.all = [];
    const opts = createAnalytics({ writeKey: "dpa_w", host: "https://dp", fetch: fetchNoop, persistence: "memory", autocapturePageviews: false, autocaptureWebVitals: { sampleRate: 0 } });
    expect(FakePO.all).toHaveLength(0);
    await opts.shutdown();
  });

  it("is a no-op in Node", () => {
    const a = createAnalytics({ writeKey: "dpa_w", host: "https://dp", fetch: fetchNoop });
    expect(() => a.captureWebVitals()()).not.toThrow();
  });
});
