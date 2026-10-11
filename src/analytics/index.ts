import { assertSecureUrl } from "../config.js";

/**
 * DevPulse product analytics. Works in browsers (automatic page views,
 * sessions, persistence, sendBeacon on page hide) and in Node (pass a
 * distinctId per call). Events are batched and retried with backoff.
 */

export type Properties = Record<string, unknown>;

/** Anything with `allFlags()`, e.g. a DevPulse feature-flag client. */
export type FlagSource = { allFlags(): Record<string, unknown> };

export type AnalyticsOptions = {
  /** The project's public write key (dpa_…). */
  writeKey: string;
  /** Your DevPulse URL, e.g. https://devpulse.example.com (https required except on localhost). */
  host: string;
  /** Capture $pageview on load and on client-side navigation (browsers). Default true. */
  autocapturePageviews?: boolean;
  /** Send when this many events are queued. Default 20 (1 in Node is not needed: use flush()). */
  flushAt?: number;
  /** Send queued events this often, in ms. Default 2000 in browsers, 10000 in Node. */
  flushInterval?: number;
  /** Events kept while offline; the oldest are dropped past this. Default 1000. */
  maxQueueSize?: number;
  /** Where the anonymous id, super properties and session live. Default localStorage in browsers. */
  persistence?: "localStorage" | "memory";
  /** A new session starts after this much inactivity. Default 30. */
  sessionTimeoutMinutes?: number;
  /** Adds `$feature/<key>` properties with each flag's current value to every event. */
  flags?: FlagSource;
  /** Don't send anything when the browser's Do Not Track is on. Default false. */
  respectDoNotTrack?: boolean;
  /** Start opted out (e.g. until the user accepts a consent banner). */
  optedOut?: boolean;
  /**
   * Send $current_url / $referrer with their full query string and fragment. Default false:
   * the fragment is dropped and only campaign parameters (utm_*, gclid, fbclid, ref) are kept,
   * so OAuth codes, reset tokens and the like never leave the page.
   */
  captureFullUrls?: boolean;
  fetch?: typeof fetch;
  onError?: (err: Error) => void;
};

export type CaptureOptions = {
  /** Server-side: who did it. Defaults to the current browser user. */
  distinctId?: string;
  timestamp?: Date;
  $set?: Properties;
  $set_once?: Properties;
};

type Event = { uuid: string; event: string; distinct_id: string; timestamp: string; properties: Properties; $set?: Properties; $set_once?: Properties };
type State = { distinctId: string; identified: boolean; props: Properties; session?: { id: string; last: number; start: number }; initialSent?: boolean; optedOut?: boolean };

export const VERSION = "0.1.0";
const KEPT_QUERY_PARAMS = new Set(["utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "gclid", "fbclid", "ref"]);

/** Drop the fragment and every query parameter outside the campaign allowlist. */
export function sanitizeUrl(raw: string): string {
  if (!raw) return raw;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return raw.split(/[?#]/)[0]!;
  }
  url.hash = "";
  for (const key of [...url.searchParams.keys()]) {
    if (!KEPT_QUERY_PARAMS.has(key)) url.searchParams.delete(key);
  }
  return url.toString();
}

const isBrowser = typeof window !== "undefined" && typeof document !== "undefined";
const MAX_SESSION_MS = 24 * 3_600_000;

/** Time-ordered UUID (v7). */
export function uuidv7(ms = Date.now()): string {
  const b = new Uint8Array(16);
  const c = (globalThis as { crypto?: Crypto }).crypto;
  if (c?.getRandomValues) c.getRandomValues(b);
  else for (let i = 0; i < 16; i++) b[i] = Math.floor(Math.random() * 256);
  for (let i = 0; i < 6; i++) b[i] = Math.floor(ms / 2 ** (8 * (5 - i))) % 256;
  b[6] = (b[6]! & 0x0f) | 0x70;
  b[8] = (b[8]! & 0x3f) | 0x80;
  const h = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

class Store {
  private mem: State | null = null;
  constructor(
    private key: string,
    private local: boolean,
  ) {}
  load(): State | null {
    if (this.mem) return this.mem;
    if (this.local) {
      try {
        const raw = localStorage.getItem(this.key);
        if (raw) this.mem = JSON.parse(raw) as State;
      } catch {
        /* storage blocked: memory only */
      }
    }
    return this.mem;
  }
  save(s: State) {
    this.mem = s;
    if (!this.local) return;
    try {
      localStorage.setItem(this.key, JSON.stringify(s));
    } catch {
      /* storage full or blocked */
    }
  }
}

export class Analytics {
  private opts: Required<Pick<AnalyticsOptions, "flushAt" | "flushInterval" | "maxQueueSize" | "sessionTimeoutMinutes">> & AnalyticsOptions;
  private store: Store;
  private state: State;
  private queue: Event[] = [];
  private timer: ReturnType<typeof setTimeout> | undefined;
  private sending: Promise<boolean> | null = null;
  private backoff = 0;
  private lastUrl = "";
  private cleanup: (() => void)[] = [];
  private endpoint: string;

  constructor(options: AnalyticsOptions) {
    if (!options.writeKey) throw new Error("writeKey is required");
    if (!options.host) throw new Error("host is required");
    assertSecureUrl("host", options.host);
    this.opts = { flushAt: 20, flushInterval: isBrowser ? 2000 : 10000, maxQueueSize: 1000, sessionTimeoutMinutes: 30, ...options };
    this.endpoint = `${options.host.replace(/\/+$/, "")}/a/batch`;
    this.store = new Store(`dp_analytics_${options.writeKey}`, (options.persistence ?? (isBrowser ? "localStorage" : "memory")) === "localStorage" && isBrowser);
    this.state = this.store.load() ?? { distinctId: uuidv7(), identified: false, props: {} };
    if (options.optedOut !== undefined) this.state.optedOut = options.optedOut;
    this.store.save(this.state);
    if (isBrowser) this.attachBrowser();
  }

  // ---------- Public API ----------

  /** Record an event. */
  capture(event: string, properties: Properties = {}, opts: CaptureOptions = {}) {
    if (!event || this.disabled()) return;
    const now = opts.timestamp ?? new Date();
    const props: Properties = { ...this.context(), ...this.state.props, ...this.flagProps(), ...properties };
    if (!opts.distinctId) props.$session_id = this.session(now.getTime());
    const e: Event = { uuid: uuidv7(now.getTime()), event, distinct_id: opts.distinctId ?? this.state.distinctId, timestamp: now.toISOString(), properties: props };
    if (opts.$set) e.$set = opts.$set;
    if (opts.$set_once) e.$set_once = opts.$set_once;
    this.enqueue(e);
  }

  /** Record a page view (automatic unless autocapturePageviews is false). */
  pageview(properties: Properties = {}) {
    if (!isBrowser) return this.capture("$pageview", properties);
    this.lastUrl = location.href;
    const url = this.url(location.href);
    const utm = Object.fromEntries([...new URLSearchParams(location.search)].filter(([k]) => /^utm_(source|medium|campaign|term|content)$/.test(k)));
    let setOnce: Properties | undefined;
    if (!this.state.initialSent) {
      setOnce = {
        $initial_referrer: document.referrer ? this.url(document.referrer) : "$direct",
        $initial_referring_domain: referringDomain(document.referrer) ?? "$direct",
        $initial_current_url: url,
        $initial_pathname: location.pathname,
        ...Object.fromEntries(Object.entries(utm).map(([k, v]) => [`$initial_${k}`, v])),
      };
      this.state.initialSent = true;
      this.store.save(this.state);
    }
    this.capture("$pageview", { $title: document.title, ...utm, ...properties }, { $set_once: setOnce });
  }

  /**
   * Link this browser to a known user. Events from before (the anonymous id)
   * are merged into the user's profile. Optionally set person properties.
   */
  identify(distinctId: string, set?: Properties, setOnce?: Properties) {
    if (!distinctId || this.disabled()) return;
    const previous = this.state.distinctId;
    if (previous === distinctId) {
      if (set || setOnce) this.setPersonProperties(set, setOnce);
      return;
    }
    this.state = { ...this.state, distinctId, identified: true };
    this.store.save(this.state);
    this.capture("$identify", { $anon_distinct_id: previous }, { $set: set, $set_once: setOnce });
  }

  /** Update the current person's properties. */
  setPersonProperties(set?: Properties, setOnce?: Properties, opts: { distinctId?: string } = {}) {
    this.capture("$set", {}, { distinctId: opts.distinctId, $set: set, $set_once: setOnce });
  }

  /** Properties sent with every event from now on (persisted in browsers). */
  register(properties: Properties) {
    this.state = { ...this.state, props: { ...this.state.props, ...properties } };
    this.store.save(this.state);
  }

  unregister(key: string) {
    const props = { ...this.state.props };
    delete props[key];
    this.state = { ...this.state, props };
    this.store.save(this.state);
  }

  /** On logout: a new anonymous id, no super properties, a new session. */
  reset() {
    this.state = { distinctId: uuidv7(), identified: false, props: {}, optedOut: this.state.optedOut, initialSent: this.state.initialSent };
    this.store.save(this.state);
  }

  optOut() {
    this.state = { ...this.state, optedOut: true };
    this.store.save(this.state);
    this.queue = [];
  }

  optIn() {
    this.state = { ...this.state, optedOut: false };
    this.store.save(this.state);
  }

  hasOptedOut() {
    return !!this.state.optedOut;
  }

  getDistinctId() {
    return this.state.distinctId;
  }

  getSessionId() {
    return this.state.session?.id ?? null;
  }

  /** Send everything queued now. */
  async flush(): Promise<void> {
    clearTimeout(this.timer);
    this.timer = undefined;
    while (this.queue.length) {
      if (this.sending) await this.sending;
      else {
        this.sending = this.send().finally(() => (this.sending = null));
        const ok = await this.sending;
        if (!ok) return;
      }
    }
  }

  /** Flush and detach listeners (call before a Node process exits). */
  async shutdown() {
    for (const fn of this.cleanup.splice(0)) fn();
    await this.flush();
  }

  // ---------- Internals ----------

  private disabled() {
    if (this.state.optedOut) return true;
    if (this.opts.respectDoNotTrack && isBrowser) {
      const nav = navigator as Navigator & { msDoNotTrack?: string };
      return nav.doNotTrack === "1" || nav.msDoNotTrack === "1" || (window as unknown as { doNotTrack?: string }).doNotTrack === "1";
    }
    return false;
  }

  private context(): Properties {
    const base: Properties = { $lib: "devpulse-analytics", $lib_version: VERSION };
    if (!isBrowser) return base;
    return {
      ...base,
      $current_url: this.url(location.href),
      $host: location.host,
      $pathname: location.pathname,
      $referrer: document.referrer ? this.url(document.referrer) : "$direct",
      $referring_domain: referringDomain(document.referrer) ?? "$direct",
      $screen_width: screen.width,
      $screen_height: screen.height,
      $viewport_width: window.innerWidth,
      $viewport_height: window.innerHeight,
      $browser_language: navigator.language,
      $device_id: this.state.identified ? undefined : this.state.distinctId,
    };
  }

  private url(raw: string): string {
    return this.opts.captureFullUrls ? raw : sanitizeUrl(raw);
  }

  private flagProps(): Properties {
    if (!this.opts.flags) return {};
    try {
      const all = this.opts.flags.allFlags();
      return Object.fromEntries(Object.entries(all).map(([k, v]) => [`$feature/${k}`, v]));
    } catch {
      return {};
    }
  }

  /** Rolling session: renewed after inactivity or at most every 24 hours. */
  private session(now: number) {
    const s = this.state.session;
    const timeout = this.opts.sessionTimeoutMinutes * 60_000;
    if (!s || now - s.last > timeout || now - s.start > MAX_SESSION_MS) this.state.session = { id: uuidv7(now), last: now, start: now };
    else s.last = now;
    this.store.save(this.state);
    return this.state.session!.id;
  }

  private enqueue(e: Event) {
    this.queue.push(e);
    if (this.queue.length > this.opts.maxQueueSize) this.queue.splice(0, this.queue.length - this.opts.maxQueueSize);
    if (this.queue.length >= this.opts.flushAt && !this.backoff) void this.flush();
    else this.schedule();
  }

  private schedule() {
    if (this.timer) return;
    this.timer = setTimeout(() => {
      this.timer = undefined;
      void this.flush();
    }, this.backoff || this.opts.flushInterval);
    (this.timer as { unref?: () => void }).unref?.();
  }

  /** Send one batch; on failure requeue it and back off. Resolves true when sent (or dropped as invalid). */
  private async send(): Promise<boolean> {
    const batch = this.queue.splice(0, 100);
    if (!batch.length) return true;
    const f = this.opts.fetch ?? globalThis.fetch;
    try {
      const res = await f(this.endpoint, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ api_key: this.opts.writeKey, batch, sent_at: new Date().toISOString() }),
        keepalive: isBrowser,
      });
      if (res.ok || (res.status >= 400 && res.status < 500 && res.status !== 429)) {
        if (!res.ok) this.opts.onError?.(new Error(`DevPulse analytics rejected ${batch.length} events: HTTP ${res.status}`));
        this.backoff = 0;
        return true;
      }
      throw new Error(`HTTP ${res.status}`);
    } catch (err) {
      this.queue.unshift(...batch);
      this.backoff = Math.min(60_000, (this.backoff || 1000) * 2);
      this.opts.onError?.(err as Error);
      this.schedule();
      return false;
    }
  }

  /** On page hide, hand the queue to sendBeacon so it survives navigation. */
  private beacon() {
    if (!this.queue.length || typeof navigator.sendBeacon !== "function") return;
    const batch = this.queue.splice(0, 100);
    const body = JSON.stringify({ api_key: this.opts.writeKey, batch, sent_at: new Date().toISOString() });
    // text/plain avoids a CORS preflight, which beacons can't do.
    if (!navigator.sendBeacon(this.endpoint, new Blob([body], { type: "text/plain" }))) this.queue.unshift(...batch);
  }

  private attachBrowser() {
    const onHide = () => document.visibilityState === "hidden" && this.beacon();
    const onPageHide = () => this.beacon();
    document.addEventListener("visibilitychange", onHide);
    window.addEventListener("pagehide", onPageHide);
    this.cleanup.push(() => {
      document.removeEventListener("visibilitychange", onHide);
      window.removeEventListener("pagehide", onPageHide);
    });
    if (this.opts.autocapturePageviews === false) return;
    const onNav = () => {
      // Route changes fire before the new title is set; give the app a tick.
      setTimeout(() => location.href !== this.lastUrl && this.pageview(), 0);
    };
    const { pushState, replaceState } = history;
    history.pushState = function (...args: Parameters<History["pushState"]>) {
      pushState.apply(this, args);
      onNav();
    };
    history.replaceState = function (...args: Parameters<History["replaceState"]>) {
      replaceState.apply(this, args);
      onNav();
    };
    window.addEventListener("popstate", onNav);
    this.cleanup.push(() => {
      history.pushState = pushState;
      history.replaceState = replaceState;
      window.removeEventListener("popstate", onNav);
    });
    this.pageview();
  }
}

function referringDomain(ref: string): string | undefined {
  if (!ref) return undefined;
  try {
    return new URL(ref).hostname;
  } catch {
    return undefined;
  }
}

export function createAnalytics(options: AnalyticsOptions) {
  return new Analytics(options);
}
