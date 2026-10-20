import { assertSecureUrl } from "../secure-url.js";
import { DevPulseHttpError, readText, send, userAgent, type HttpOptions } from "../common/http.js";

/**
 * Heartbeat pings for DevPulse cron checks (`/ping/{token}`), fetch only.
 *
 * The ping token is part of the URL by design of the protocol (like Healthchecks.io): treat the
 * ping URL as a secret, keep it in an environment variable, and never log it.
 */

/** DevPulse keeps the first 10,000 characters of a POST body with the ping. */
export const MAX_PING_BODY = 10_000;

export type CronMonitorOptions = HttpOptions & {
  /** The check's ping URL from DevPulse, e.g. https://devpulse.example.com/ping/<token>. */
  pingUrl: string;
  /** Called when a ping fails; pings never throw (a monitoring outage must not fail the job). */
  onError?: (err: unknown) => void;
};

export type PingResult = { ok: boolean; status: number };

export class CronMonitor {
  readonly #url: string;
  private readonly o: Omit<CronMonitorOptions, "pingUrl">;

  constructor(options: CronMonitorOptions) {
    if (!options.pingUrl) throw new Error("pingUrl is required");
    assertSecureUrl("pingUrl", options.pingUrl);
    const u = new URL(options.pingUrl);
    if (!/^\/ping\/[^/]+\/?$/.test(u.pathname) || u.search || u.hash) throw new Error("pingUrl must look like https://<host>/ping/<token>");
    this.#url = `${u.origin}${u.pathname.replace(/\/$/, "")}`;
    // Keep the token-bearing URL only in #url, so util.inspect / console.log never prints it.
    const { pingUrl: _drop, ...rest } = options;
    this.o = rest;
  }

  /** Never serialize the ping URL (it holds the token). */
  toJSON() {
    return { pingUrl: "[redacted]" };
  }

  private async ping(suffix: string, body?: string): Promise<PingResult> {
    try {
      const init: RequestInit = { method: body === undefined ? "GET" : "POST", headers: { "user-agent": userAgent("Cron") } };
      if (body !== undefined) {
        init.body = body.slice(0, MAX_PING_BODY);
        (init.headers as Record<string, string>)["content-type"] = "text/plain; charset=utf-8";
      }
      const res = await send(this.#url + suffix, init, this.o);
      if (!res.ok) {
        this.o.onError?.(new DevPulseHttpError("Cron ping", res.status, await readText(res, 200)));
        return { ok: false, status: res.status };
      }
      await res.body?.cancel().catch(() => {});
      return { ok: true, status: res.status };
    } catch (err) {
      this.o.onError?.(err);
      return { ok: false, status: 0 };
    }
  }

  /** The job started (enables duration and stuck-run detection). */
  start(body?: string) {
    return this.ping("/start", body);
  }
  /** The job succeeded. An optional body (e.g. output) is stored with the ping. */
  success(body?: string) {
    return this.ping("", body);
  }
  /** The job failed. */
  fail(body?: string) {
    return this.ping("/fail", body);
  }
  /** Record a message without changing the check's state. */
  log(body: string) {
    return this.ping("/log", body);
  }
  /** Report an exit code: 0 is success, 1 to 255 is failure. */
  exitCode(code: number, body?: string) {
    if (!Number.isInteger(code) || code < 0 || code > 255) throw new RangeError("exit code must be an integer from 0 to 255");
    return this.ping(`/${code}`, body);
  }

  /**
   * Run `fn` between a start ping and a success ping, or a fail ping carrying the error text
   * (the error is rethrown). Pinging never changes the job's result.
   */
  async wrap<T>(fn: () => T | Promise<T>): Promise<T> {
    await this.start();
    let result: T;
    try {
      result = await fn();
    } catch (err) {
      const text = err instanceof Error ? `${err.name}: ${err.message}${err.stack ? `\n${err.stack}` : ""}` : String(err);
      await this.fail(text);
      throw err;
    }
    await this.success();
    return result;
  }
}

export function createCronMonitor(options: CronMonitorOptions) {
  return new CronMonitor(options);
}
