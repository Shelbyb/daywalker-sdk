import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { createAnalytics, uuidv7 } from "../src/analytics/index.js";

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
});
