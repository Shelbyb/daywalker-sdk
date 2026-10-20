import type { ApiClient } from "../api/index.js";

/**
 * Push good/total events to a custom (push) SLO through the management API:
 * `POST /api/v1/projects/{project}/slos/{slo}/events` (scope `slo:ingest`).
 *
 * Counts are deltas added to their time bucket and the endpoint is NOT idempotent: resending a
 * batch counts it twice. So the reporter aggregates counts per minute, sends each batch once, and
 * does not retry a batch whose outcome is unknown (network error or timeout); it reports it to
 * `onError` instead. 429 is retried by the API client before the request is accepted.
 */

export type SloReporterOptions = {
  /** An API client with the `slo:ingest` scope. */
  api: Pick<ApiClient, "post">;
  /** Project key. */
  project: string;
  /** SLO key. */
  slo: string;
  /** Flush at least this often, in ms. Default 10000; 0 disables the timer. */
  flushIntervalMs?: number;
  onError?: (err: unknown, events: SloEvent[]) => void;
  /** Test seam. */
  now?: () => number;
};

export type SloEvent = { good: number; total: number; timestamp?: string };

/** DevPulse accepts at most this many events per request. */
export const MAX_SLO_EVENTS = 1000;

export class SloReporter {
  private readonly path: string;
  private readonly o: SloReporterOptions;
  private buckets = new Map<number, { good: number; total: number }>();
  private timer: ReturnType<typeof setInterval> | undefined;
  private flushing: Promise<void> | null = null;

  constructor(options: SloReporterOptions) {
    if (!options.api) throw new Error("api is required");
    if (!options.project || !options.slo) throw new Error("project and slo are required");
    this.path = `/api/v1/projects/${encodeURIComponent(options.project)}/slos/${encodeURIComponent(options.slo)}/events`;
    this.o = options;
    const interval = options.flushIntervalMs ?? 10_000;
    if (interval > 0) {
      // flush() only rejects if onError itself throws; never let that become an unhandled rejection.
      this.timer = setInterval(() => void this.flush().catch(() => {}), interval);
      (this.timer as { unref?: () => void }).unref?.();
    }
  }

  /** Add counts (e.g. `record(ok ? 1 : 0, 1)` per request). Aggregated per minute until flushed. */
  record(good: number, total: number, at?: Date): void {
    if (!Number.isInteger(good) || !Number.isInteger(total) || good < 0 || total < 0 || good > total) throw new RangeError("good and total must be integers with 0 <= good <= total");
    const ms = at ? at.getTime() : (this.o.now ?? Date.now)();
    // An Invalid Date would become a NaN bucket whose toISOString() throws on every flush.
    if (!Number.isFinite(ms)) throw new RangeError("at must be a valid Date");
    if (total === 0) return;
    const minute = Math.floor(ms / 60_000) * 60_000;
    const b = this.buckets.get(minute) ?? { good: 0, total: 0 };
    b.good += good;
    b.total += total;
    this.buckets.set(minute, b);
  }

  /** Shortcut for `record(ok ? 1 : 0, 1)`. */
  observe(ok: boolean, at?: Date) {
    this.record(ok ? 1 : 0, 1, at);
  }

  /** Send the aggregated events now. */
  flush(): Promise<void> {
    this.flushing ??= this.drain().finally(() => (this.flushing = null));
    return this.flushing;
  }

  private async drain() {
    const events: SloEvent[] = [...this.buckets.entries()].sort(([a], [b]) => a - b).map(([t, c]) => ({ good: c.good, total: c.total, timestamp: new Date(t).toISOString() }));
    this.buckets.clear();
    for (let i = 0; i < events.length; i += MAX_SLO_EVENTS) {
      const batch = events.slice(i, i + MAX_SLO_EVENTS);
      try {
        await this.o.api.post(this.path, { events: batch });
      } catch (err) {
        this.o.onError?.(err, batch);
      }
    }
  }

  async shutdown(): Promise<void> {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
    await this.flush();
  }
}

export function createSloReporter(options: SloReporterOptions) {
  return new SloReporter(options);
}

/** Send events once, without batching. Throws `ApiProblemError` on rejection. */
export async function pushSloEvents(api: Pick<ApiClient, "post">, project: string, slo: string, events: SloEvent | SloEvent[]) {
  const list = Array.isArray(events) ? events : [events];
  if (!list.length || list.length > MAX_SLO_EVENTS) throw new RangeError(`send 1 to ${MAX_SLO_EVENTS} events`);
  const res = await api.post(`/api/v1/projects/${encodeURIComponent(project)}/slos/${encodeURIComponent(slo)}/events`, { events: list });
  return res.data;
}
