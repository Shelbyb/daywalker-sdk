import { baseUrl, DevPulseHttpError, readText, retryAfterSeconds, send, userAgent, type HttpOptions } from "../common/http.js";

/**
 * DevPulse on-call Events API v2 (PagerDuty-compatible): `POST {host}/oncall/v2/enqueue` to
 * trigger, acknowledge or resolve pages for an escalation policy's routing key. Fetch only.
 *
 * Use a stable `dedupKey` per problem (e.g. "db-primary-disk-full"): repeated triggers with the
 * same key update one page instead of opening new ones, and acknowledge/resolve need it.
 */

export type OncallSeverity = "critical" | "error" | "warning" | "info";

export type OncallOptions = HttpOptions & {
  /** Your DevPulse URL, e.g. https://devpulse.example.com. */
  host: string;
  /** The escalation policy's routing key (sent in the JSON body, never in the URL). */
  routingKey: string;
};

export type TriggerInput = {
  summary: string;
  severity?: OncallSeverity;
  source?: string;
  dedupKey?: string;
  component?: string;
  group?: string;
  class?: string;
  /** Extra details, under 64 KB as JSON. */
  customDetails?: Record<string, unknown>;
  /** Up to 10 links. */
  links?: { href: string; text?: string }[];
};

export type OncallResult = { status: string; message: string; dedupKey: string };

const MAX_BODY = 512 * 1024;

export class OncallClient {
  private readonly url: string;
  readonly #key: string;
  private readonly o: HttpOptions;

  constructor(options: OncallOptions) {
    this.url = `${baseUrl("host", options.host)}/oncall/v2/enqueue`;
    if (!options.routingKey) throw new Error("routingKey is required");
    this.#key = options.routingKey;
    this.o = { fetch: options.fetch, timeoutMs: options.timeoutMs };
  }

  toJSON() {
    return { url: this.url };
  }

  private async send(event: Record<string, unknown>): Promise<OncallResult> {
    const body = JSON.stringify({ routing_key: this.#key, ...event });
    if (body.length > MAX_BODY) throw new Error("On-call event is larger than 512 KB");
    const res = await send(this.url, { method: "POST", headers: { "content-type": "application/json", accept: "application/json", "user-agent": userAgent("Oncall") }, body }, this.o);
    if (!res.ok) throw new DevPulseHttpError("On-call event", res.status, await readText(res, 1000), retryAfterSeconds(res));
    const json = (await res.json().catch(() => ({}))) as { status?: string; message?: string; dedup_key?: string };
    return { status: json.status ?? "success", message: json.message ?? "", dedupKey: json.dedup_key ?? String(event.dedup_key ?? "") };
  }

  /** Open (or update) a page. Returns the dedup key to acknowledge or resolve it later. */
  trigger(input: TriggerInput): Promise<OncallResult> {
    if (!input.summary) throw new Error("summary is required");
    return this.send({
      event_action: "trigger",
      dedup_key: input.dedupKey,
      payload: {
        summary: input.summary.slice(0, 1024),
        severity: input.severity ?? "error",
        source: input.source ?? "",
        component: input.component,
        group: input.group,
        class: input.class,
        custom_details: input.customDetails,
      },
      links: input.links,
    });
  }

  acknowledge(dedupKey: string): Promise<OncallResult> {
    if (!dedupKey) throw new Error("dedupKey is required");
    return this.send({ event_action: "acknowledge", dedup_key: dedupKey });
  }

  resolve(dedupKey: string): Promise<OncallResult> {
    if (!dedupKey) throw new Error("dedupKey is required");
    return this.send({ event_action: "resolve", dedup_key: dedupKey });
  }
}

export function createOncall(options: OncallOptions) {
  return new OncallClient(options);
}
