/**
 * Real-user Web Vitals for DevPulse (`POST {host}/a/rum`). Measures LCP, CLS (largest session
 * window), INP (event timing), FCP, TTFB and page load with PerformanceObserver and navigation
 * timing, and sends them with sendBeacon (fetch keepalive as the fallback) when the page is hidden.
 * CLS and INP are re-sent when they grow; the server keeps the largest value per page view.
 * Mirrors the reference script DevPulse serves at /a/rum.js. Paths are normalized by the server.
 */

export type WebVitalsOptions = {
  /** Share of page views to measure, 0 to 1, decided once per page view. Default 1. */
  sampleRate?: number;
  /** Release or version string (`[A-Za-z0-9_.+@/:~-]`, up to 100 characters). Ignored when invalid. */
  release?: string;
  /** e.g. "production" (`[A-Za-z0-9_.-]`, up to 64 characters). Ignored when invalid. */
  environment?: string;
  /** Page path to report instead of `location.pathname`, e.g. a route pattern like "/users/:id". */
  path?: string;
};

export type WebVitalMetric = "LCP" | "CLS" | "INP" | "FCP" | "TTFB" | "LOAD";

/** One metric in the `/a/rum` payload. */
export type WebVitalEvent = { name: WebVitalMetric; value: number; selector?: string };

/** The `/a/rum` request body. */
export type WebVitalsPayload = {
  key: string;
  pageId: string;
  navigationType: string;
  path: string;
  release?: string;
  environment?: string;
  connection?: string;
  device?: "tablet";
  events: WebVitalEvent[];
};

/** What the analytics client hands over: its write key, endpoint and consent state. */
export type WebVitalsContext = {
  writeKey: string;
  endpoint: string;
  /** Whether the client is opted out right now (checked again at every send). */
  isOptedOut: () => boolean;
  /** Applies the client's sanitizePath to location.pathname. */
  sanitizePath: (path: string) => string;
  fetch?: typeof fetch;
  onError?: (err: Error) => void;
};

const RELEASE = /^[\w.+@/:~-]+$/;
const ENVIRONMENT = /^[\w.-]+$/;
const CONNECTIONS = new Set(["slow-2g", "2g", "3g", "4g"]);
const MAX_SELECTOR = 200;

type Entry = PerformanceEntry & Record<string, any>;
type Stored = { v: number; t?: string };

/** A short CSS selector: up to four levels, stopping at an id. */
function selectorOf(node: unknown): string | undefined {
  let el = node as Element | null | undefined;
  if (el && el.nodeType !== 1) el = el.parentElement;
  const parts: string[] = [];
  for (; el && el.nodeType === 1 && parts.length < 4; el = el.parentElement) {
    const p = el.localName;
    if (el.id) {
      parts.unshift(`${p}#${el.id}`);
      break;
    }
    const c = typeof el.className === "string" ? el.className.trim().split(/\s+/).filter(Boolean).slice(0, 2).join(".") : "";
    parts.unshift(c ? `${p}.${c}` : p);
    if (p === "body") break;
  }
  return parts.join(">").slice(0, MAX_SELECTOR) || undefined;
}

const round = (name: string, v: number) => (name === "CLS" ? Math.round(v * 1e4) / 1e4 : Math.round(v * 10) / 10);

const newId = (): string => {
  const c = (globalThis as { crypto?: Crypto }).crypto;
  return c?.randomUUID ? c.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 12)}`;
};

/** Do Not Track or Global Privacy Control is on. */
export function privacySignalOn(): boolean {
  const nav = globalThis.navigator as (Navigator & { globalPrivacyControl?: boolean; msDoNotTrack?: string }) | undefined;
  const win = (globalThis as { window?: { doNotTrack?: string } }).window;
  return nav?.globalPrivacyControl === true || nav?.doNotTrack === "1" || nav?.msDoNotTrack === "1" || win?.doNotTrack === "1";
}

/**
 * Start measuring this page view. Returns a function that stops it (removes listeners and
 * observers). Does nothing, and returns a no-op, outside browsers, without PerformanceObserver,
 * when DNT or GPC is on, or when the page view is not sampled.
 */
export function startWebVitals(ctx: WebVitalsContext, options: WebVitalsOptions = {}): () => void {
  const noop = () => {};
  const g = globalThis as unknown as { window?: Window; document?: Document; PerformanceObserver?: typeof PerformanceObserver; performance?: Performance; navigator?: Navigator; location?: Location };
  const w = g.window;
  const d = g.document;
  const P = g.PerformanceObserver;
  const perf = g.performance;
  const n = g.navigator;
  if (!w || !d || !P || !perf || !n) return noop;
  if (privacySignalOn()) return noop;
  let rate = options.sampleRate ?? 1;
  if (!(rate >= 0 && rate <= 1)) rate = 1;
  if (Math.random() >= rate) return noop;

  const release = options.release && options.release.length <= 100 && RELEASE.test(options.release) ? options.release : undefined;
  const environment = options.environment && options.environment.length <= 64 && ENVIRONMENT.test(options.environment) ? options.environment : undefined;
  const eff = (n as Navigator & { connection?: { effectiveType?: string } }).connection?.effectiveType;
  const connection = eff && CONNECTIONS.has(eff) ? eff : undefined;
  const tablet = n.maxTouchPoints > 1 && /Macintosh/.test(n.userAgent);

  const navEntry = () => perf.getEntriesByType?.("navigation")[0] as PerformanceNavigationTiming | undefined;
  const activation = () => (navEntry() as { activationStart?: number } | undefined)?.activationStart || 0;
  let pageId = newId();
  let navType = (() => {
    const e = navEntry();
    if ((d as Document & { prerendering?: boolean }).prerendering || activation() > 0) return "prerender";
    if ((d as Document & { wasDiscarded?: boolean }).wasDiscarded) return "restore";
    return e?.type ? e.type.replace(/_/g, "-") : "navigate";
  })();
  let firstHidden = d.visibilityState === "hidden" && !(d as Document & { prerendering?: boolean }).prerendering ? 0 : Infinity;
  let vals: Record<string, Stored> = {};
  let sent: Record<string, number> = {};
  const observers: { o: PerformanceObserver; cb: (list: Entry[]) => void }[] = [];
  const set = (name: string, v: number, t?: string) => void (vals[name] = { v, t });

  const observe = (type: string, cb: (list: Entry[]) => void, extra?: Record<string, unknown>): boolean => {
    try {
      if (P.supportedEntryTypes && !P.supportedEntryTypes.includes(type)) return false;
      const o = new P((list) => cb(list.getEntries() as Entry[]));
      o.observe({ type, buffered: true, ...extra } as PerformanceObserverInit);
      observers.push({ o, cb });
      return true;
    } catch {
      return false;
    }
  };

  observe("paint", (list) => {
    for (const e of list) if (e.name === "first-contentful-paint" && e.startTime < firstHidden) set("FCP", Math.max(e.startTime - activation(), 0));
  });

  observe("largest-contentful-paint", (list) => {
    const e = list[list.length - 1];
    if (e && e.startTime < firstHidden) set("LCP", Math.max(e.startTime - activation(), 0), selectorOf(e.element));
  });

  // CLS: the largest burst of shifts (gaps < 1 s, burst < 5 s), not their lifetime sum.
  let cls = 0;
  let sv = 0;
  let se: Entry[] = [];
  let sMax = 0;
  let sTarget: string | undefined;
  const resetCls = () => {
    cls = 0;
    sv = 0;
    se = [];
    sMax = 0;
    sTarget = undefined;
    set("CLS", 0);
  };
  const hasCls = observe("layout-shift", (list) => {
    for (const e of list) {
      if (e.hadRecentInput) continue;
      const first = se[0];
      const last = se[se.length - 1];
      if (sv && e.startTime - last!.startTime < 1000 && e.startTime - first!.startTime < 5000) {
        sv += e.value;
        se.push(e);
      } else {
        sv = e.value;
        se = [e];
        sMax = 0;
        sTarget = undefined;
      }
      const sources = e.sources as { node?: Node }[] | undefined;
      if (e.value > sMax && sources?.length) {
        sMax = e.value;
        const src = sources.find((x) => x.node && x.node.nodeType === 1) ?? sources[0];
        sTarget = selectorOf(src!.node);
      }
      if (sv > cls) {
        cls = sv;
        set("CLS", cls, sTarget);
      }
    }
  });
  if (hasCls) resetCls();

  // INP: the slowest interaction, or for pages with many, roughly the 98th percentile (skip one per 50).
  let longest: { id: number; d: number; t?: string }[] = [];
  let byId: Record<number, { id: number; d: number; t?: string }> = {};
  let count = 0;
  const onEvent = (list: Entry[]) => {
    for (const e of list) {
      if (!e.interactionId) continue;
      let cur = byId[e.interactionId];
      if (cur) {
        if (e.duration > cur.d) {
          cur.d = e.duration;
          cur.t = selectorOf(e.target) || cur.t;
        }
      } else {
        count++;
        cur = byId[e.interactionId] = { id: e.interactionId, d: e.duration, t: selectorOf(e.target) };
        longest.push(cur);
      }
      longest.sort((a, b) => b.d - a.d);
      for (const x of longest.splice(10)) delete byId[x.id];
    }
    const total = (perf as Performance & { interactionCount?: number }).interactionCount || count;
    const pick = longest[Math.min(longest.length - 1, Math.floor(total / 50))];
    if (pick) set("INP", pick.d, pick.t);
  };
  observe("event", onEvent, { durationThreshold: 40 });
  observe("first-input", onEvent);

  const flush = () => {
    if (ctx.isOptedOut() || privacySignalOn()) return;
    for (const x of observers) {
      const r = x.o.takeRecords?.();
      if (r?.length) x.cb(r as Entry[]);
    }
    const e = navEntry();
    const a = activation();
    if (e && e.responseStart > 0 && !vals.TTFB) set("TTFB", Math.max(e.responseStart - a, 0));
    if (e && e.loadEventEnd > 0 && !vals.LOAD) set("LOAD", Math.max(e.loadEventEnd - a, 0));
    const events: WebVitalEvent[] = [];
    for (const [k, s] of Object.entries(vals)) {
      const v = round(k, s.v);
      // LCP, FCP, TTFB and LOAD are final once sent; CLS and INP can still grow.
      if (sent[k] === undefined || ((k === "CLS" || k === "INP") && v > sent[k]!)) {
        events.push({ name: k as WebVitalMetric, value: v, selector: s.t });
        sent[k] = v;
      }
    }
    if (!events.length) return;
    const path = options.path ?? safePath(ctx, g.location?.pathname ?? "/");
    const body: WebVitalsPayload = { key: ctx.writeKey, pageId, navigationType: navType, path: path.slice(0, 2048), release, environment, connection, device: tablet ? "tablet" : undefined, events };
    transmit(ctx, JSON.stringify(body));
  };

  const onVisibility = () => {
    if (d.visibilityState !== "hidden") return;
    if (firstHidden === Infinity) firstHidden = perf.now();
    flush();
  };
  // Restored from the back/forward cache: a new page view for CLS and INP.
  const onPageShow = (ev: Event) => {
    if (!(ev as PageTransitionEvent).persisted) return;
    pageId = newId();
    navType = "back-forward-cache";
    vals = {};
    sent = {};
    longest = [];
    byId = {};
    count = 0;
    if (hasCls) resetCls();
  };
  d.addEventListener("visibilitychange", onVisibility, true);
  w.addEventListener("pagehide", flush, true);
  w.addEventListener("pageshow", onPageShow, true);

  let stopped = false;
  return () => {
    if (stopped) return;
    stopped = true;
    d.removeEventListener("visibilitychange", onVisibility, true);
    w.removeEventListener("pagehide", flush, true);
    w.removeEventListener("pageshow", onPageShow, true);
    for (const x of observers.splice(0)) x.o.disconnect();
  };
}

function safePath(ctx: WebVitalsContext, pathname: string): string {
  try {
    return ctx.sanitizePath(pathname);
  } catch (err) {
    ctx.onError?.(err as Error);
    return "/";
  }
}

/** sendBeacon (text/plain, no CORS preflight), then fetch with keepalive when it is missing or refuses. */
function transmit(ctx: WebVitalsContext, body: string) {
  const nav = globalThis.navigator;
  try {
    if (typeof nav.sendBeacon === "function" && nav.sendBeacon(ctx.endpoint, body)) return;
  } catch {
    /* fall through to fetch */
  }
  const f = ctx.fetch ?? globalThis.fetch;
  try {
    Promise.resolve(f(ctx.endpoint, { method: "POST", body, keepalive: true, credentials: "omit", headers: { "content-type": "text/plain" } })).catch((err: unknown) => ctx.onError?.(err as Error));
  } catch (err) {
    ctx.onError?.(err as Error);
  }
}
