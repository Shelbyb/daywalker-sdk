import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { createCronMonitor, MAX_PING_BODY } from "../src/cron/index.js";
import { consoleAdapter, createLogger, LOG_LIMITS, pinoDestination, type LoggerOptions } from "../src/logs/index.js";
import { fetchDotenv, fetchSecrets, parseDotenv } from "../src/secrets/index.js";
import { loadSecrets } from "../src/secrets/env.js";
import { createOncall } from "../src/oncall/index.js";
import { createSloReporter, MAX_SLO_EVENTS, pushSloEvents } from "../src/slo/index.js";
import { recordDeploy } from "../src/deploys/index.js";
import { DevPulseHttpError, baseUrl } from "../src/common/http.js";

type Call = { url: string; init: RequestInit };
function mock(handler: (url: string, init: RequestInit, n: number) => Response | Promise<Response> = () => new Response("OK")) {
  const calls: Call[] = [];
  const fetch = (async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return handler(url, init, calls.length);
  }) as unknown as typeof globalThis.fetch;
  return { calls, fetch };
}
const hdr = (c: Call, name: string) => (c.init.headers as Record<string, string>)[name];
async function rejects(p: Promise<unknown> | (() => unknown)): Promise<Error> {
  try {
    await (typeof p === "function" ? p() : p);
  } catch (err) {
    return err as Error;
  }
  throw new Error("should have failed");
}

describe("common http", () => {
  it("baseUrl requires https (except localhost) and trims slashes", () => {
    expect(baseUrl("host", "https://dp.example.com//")).toBe("https://dp.example.com");
    expect(baseUrl("host", "http://localhost:3000")).toBe("http://localhost:3000");
    expect(() => baseUrl("host", "http://dp.example.com")).toThrow();
    expect(() => baseUrl("host", undefined)).toThrow();
  });
});

describe("cron", () => {
  const URL_ = "https://dp.example.com/ping/abc123";

  it("pings start, success, fail, log and exit codes with the right method and path", async () => {
    const m = mock();
    const cron = createCronMonitor({ pingUrl: `${URL_}/`, fetch: m.fetch });
    await cron.start();
    await cron.success("done");
    await cron.fail();
    await cron.log("x".repeat(MAX_PING_BODY + 50));
    await cron.exitCode(3);
    expect(m.calls.map((c) => `${c.init.method} ${c.url}`)).toEqual([`GET ${URL_}/start`, `POST ${URL_}`, `GET ${URL_}/fail`, `POST ${URL_}/log`, `GET ${URL_}/3`]);
    expect((m.calls[3]!.init.body as string).length).toBe(MAX_PING_BODY);
    expect(m.calls[0]!.init.redirect).toBe("error");
    expect(() => cron.exitCode(256)).toThrow();
    expect(JSON.stringify(cron)).toBe('{"pingUrl":"[redacted]"}');
  });

  it("rejects insecure or malformed ping URLs", () => {
    expect(() => createCronMonitor({ pingUrl: "http://dp.example.com/ping/x" })).toThrow();
    expect(() => createCronMonitor({ pingUrl: "https://dp.example.com/other/x" })).toThrow();
    expect(() => createCronMonitor({ pingUrl: "https://dp.example.com/ping/x?y=1" })).toThrow();
    expect(() => createCronMonitor({ pingUrl: "" })).toThrow();
  });

  it("never throws on ping failures and reports them to onError", async () => {
    const errors: unknown[] = [];
    let n = 0;
    const m = mock(() => {
      if (++n === 1) throw new Error("offline");
      return new Response("Not found", { status: 404 });
    });
    const cron = createCronMonitor({ pingUrl: URL_, fetch: m.fetch, onError: (e) => errors.push(e) });
    expect(await cron.success()).toEqual({ ok: false, status: 0 });
    expect(await cron.success()).toEqual({ ok: false, status: 404 });
    expect((errors[1] as DevPulseHttpError).status).toBe(404);
    const quiet = createCronMonitor({ pingUrl: URL_, fetch: m.fetch });
    expect((await quiet.fail()).ok).toBe(false);
  });

  it("wrap() pings start then success, or fail with the error text and rethrows", async () => {
    const m = mock();
    const cron = createCronMonitor({ pingUrl: URL_, fetch: m.fetch });
    expect(await cron.wrap(async () => 42)).toBe(42);
    const err = await rejects(cron.wrap(() => {
      throw new TypeError("boom");
    }));
    expect(err.message).toBe("boom");
    await rejects(cron.wrap(() => Promise.reject("plain")));
    expect(m.calls.map((c) => c.url.slice(URL_.length))).toEqual(["/start", "", "/start", "/fail", "/start", "/fail"]);
    expect(m.calls[3]!.init.body as string).toMatch(/^TypeError: boom/);
    expect(m.calls[5]!.init.body).toBe("plain");
  });
});

describe("logs", () => {
  const opts = (m: ReturnType<typeof mock>, over: Partial<LoggerOptions> = {}): LoggerOptions => ({ host: "https://dp.example.com", token: "dpl_secret", fetch: m.fetch, flushIntervalMs: 0, now: () => Date.UTC(2026, 9, 19), sleep: async () => {}, ...over });
  const sent = (c: Call) => JSON.parse(c.init.body as string) as Record<string, unknown>[];

  it("batches entries as a JSON array with bearer auth, levels and attributes", async () => {
    const m = mock(() => Response.json({ accepted: 2 }));
    const log = createLogger(opts(m, { service: "api", hostname: "web-1", defaultAttributes: { env: "prod" }, minLevel: "info" }));
    log.debug("hidden");
    log.info("user signed in", { userId: 42, message: "ignored attr" });
    log.child({ requestId: "r1" }).error("db timeout", { ms: 5003 });
    expect(log.queued).toBe(2);
    await log.flush();
    expect(m.calls).toHaveLength(1);
    expect(m.calls[0]!.url).toBe("https://dp.example.com/logs/ingest");
    expect(hdr(m.calls[0]!, "authorization")).toBe("Bearer dpl_secret");
    expect(sent(m.calls[0]!)).toEqual([
      { env: "prod", userId: 42, message: "user signed in", service: "api", host: "web-1", timestamp: "2026-10-19T00:00:00.000Z", level: "info" },
      { env: "prod", requestId: "r1", ms: 5003, service: "api", host: "web-1", timestamp: "2026-10-19T00:00:00.000Z", level: "error", message: "db timeout" },
    ]);
    expect(JSON.stringify(log)).not.toMatch(/dpl_secret/);
  });

  it("applies DevPulse's size limits to messages and attributes", async () => {
    const m = mock();
    const log = createLogger(opts(m));
    log.warn("m".repeat(LOG_LIMITS.maxMessageChars + 10), { big: "a".repeat(LOG_LIMITS.maxAttributesChars) });
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    log.info("circ", circular);
    log.raw(circular);
    await log.flush();
    const [a, b] = sent(m.calls[0]!);
    expect((a!.message as string).length).toBe(LOG_LIMITS.maxMessageChars + 1);
    expect(a!["devpulse.truncated"]).toBe(true);
    expect(b!["devpulse.unserializable"]).toBe(true);
  });

  it("flushes at flushAt, splits by bytes, drops the oldest beyond maxQueueSize and oversize entries", async () => {
    const m = mock();
    const log = createLogger(opts(m, { flushAt: 1000, maxQueueSize: 3, maxBatchBytes: 300 }));
    for (let i = 0; i < 5; i++) log.info(`line ${i} ${"x".repeat(100)}`);
    expect(log.dropped).toBe(2);
    log.raw({ message: "y".repeat(400) });
    await log.flush();
    expect(m.calls.length).toBe(2);
    const all = m.calls.flatMap(sent);
    expect(all.map((e) => (e.message as string).slice(0, 6))).toEqual(["line 3", "line 4", "log en"]);
    const auto = mock();
    const l2 = createLogger(opts(auto, { flushAt: 2 }));
    l2.info("a");
    l2.info("b");
    await l2.flush();
    expect(auto.calls.length).toBe(1);
  });

  it("retries 429/5xx/network errors, then reports; drops non-retryable batches", async () => {
    const errors: unknown[] = [];
    const seq = [() => new Response(null, { status: 429, headers: { "retry-after": "1" } }), () => { throw new Error("net"); }, () => new Response("ok")];
    const m = mock((_u, _i, n) => seq[n - 1]!());
    const sleeps: number[] = [];
    const log = createLogger(opts(m, { onError: (e) => errors.push(e), sleep: async (ms) => void sleeps.push(ms) }));
    log.info("a");
    await log.flush();
    expect(m.calls.length).toBe(3);
    expect(sleeps).toEqual([1000, 1000]);
    expect(errors).toHaveLength(0);

    const m2 = mock(() => new Response("bad token", { status: 401 }));
    const l2 = createLogger(opts(m2, { onError: (e) => errors.push(e) }));
    l2.info("a");
    await l2.flush();
    expect(m2.calls.length).toBe(1);
    expect((errors[0] as DevPulseHttpError).status).toBe(401);

    const m3 = mock(() => new Response(null, { status: 503 }));
    const l3 = createLogger(opts(m3, { onError: (e) => errors.push(e), maxRetries: 1 }));
    l3.info("a");
    await l3.shutdown();
    expect(m3.calls.length).toBe(2);
    expect((errors[1] as DevPulseHttpError).status).toBe(503);
    l3.info("after shutdown");
    l3.raw({});
    expect(l3.queued).toBe(0);
  });

  it("runs a flush timer and validates options", async () => {
    const m = mock();
    const log = createLogger(opts(m, { flushIntervalMs: 5 }));
    log.info("tick");
    await new Promise((r) => setTimeout(r, 30));
    await log.shutdown();
    expect(m.calls.length).toBe(1);
    expect(() => createLogger({ host: "https://dp.example.com", token: "" })).toThrow();
    expect(() => createLogger({ host: "http://dp.example.com", token: "t" })).toThrow();
  });

  it("consoleAdapter and pinoDestination feed the logger", async () => {
    const m = mock();
    const log = createLogger(opts(m, { minLevel: "trace" }));
    const printed: unknown[][] = [];
    const pass = { log: (...a: unknown[]) => printed.push(a), info: () => {}, warn: () => {}, error: () => {}, debug: () => {}, trace: () => {} };
    const c = consoleAdapter(log, { passthrough: pass });
    c.log("hello", { a: 1 }, new Error("inner"));
    c.error(new Error("outer"));
    c.warn({ obj: true });
    c.debug(undefined);
    c.info(10n);
    c.trace("t");
    consoleAdapter(log).info("no passthrough");
    const dest = pinoDestination(log);
    expect(dest.write('{"level":50,"msg":"pino","time":1}\n\nnot json\n[1]\n')).toBe(true);
    await log.flush();
    const all = sent(m.calls[0]!);
    expect(printed).toHaveLength(1);
    expect(all.map((e) => e.message ?? e.msg)).toEqual(["hello", "Error: outer", '{"obj":true}', "undefined", "10", "t", "no passthrough", "pino", "not json", "[1]"]);
    expect((all[0]!.args as { message?: string }[])[1]!.message).toBe("inner");
    expect(all[1]!.level).toBe("error");
    expect(typeof all[1]!.stack).toBe("string");
    expect(all[7]!.level).toBe(50);
  });
});

describe("secrets", () => {
  it("fetches JSON secrets with the bearer token in a header only", async () => {
    const m = mock(() => Response.json({ environment: "production", warnings: ["B: unresolved", 3], secrets: { A: "1", B: "", N: 5 } }));
    const r = await fetchSecrets({ host: "https://dp.example.com/", token: "dps_abc", fetch: m.fetch });
    expect({ ...r.secrets }).toEqual({ A: "1", B: "" });
    expect(r.environment).toBe("production");
    expect(r.warnings).toEqual(["B: unresolved"]);
    expect(m.calls[0]!.url).toBe("https://dp.example.com/api/v1/secrets?format=json");
    expect(m.calls[0]!.url).not.toMatch(/dps_/);
    expect(hdr(m.calls[0]!, "authorization")).toBe("Bearer dps_abc");
    expect(m.calls[0]!.init.redirect).toBe("error");
    const bare = await fetchSecrets({ host: "https://dp.example.com", token: "dps_abc", fetch: mock(() => Response.json({ secrets: {} })).fetch });
    expect(bare.environment).toBeUndefined();
    expect(bare.warnings).toEqual([]);
  });

  it("fetches and parses dotenv", async () => {
    const text = 'A=1\nexport B="multi\\nline \\"q\\" \\$HOME"\nC=\'lit #x\'\nD=plain # comment\n# skip\n';
    const m = mock(() => new Response(text));
    expect(await fetchDotenv({ host: "https://dp.example.com", token: "dps_abc", fetch: m.fetch })).toBe(text);
    expect(m.calls[0]!.url).toMatch(/format=dotenv$/);
    expect({ ...parseDotenv(text) }).toEqual({ A: "1", B: 'multi\nline "q" $HOME', C: "lit #x", D: "plain" });
  });

  it("throws typed errors", async () => {
    const e = await rejects(fetchSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: mock(() => new Response("{}", { status: 403 })).fetch }));
    expect((e as DevPulseHttpError).status).toBe(403);
    expect((await rejects(fetchSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: mock(() => Response.json({ nope: 1 })).fetch }))).message).toMatch(/Unexpected/);
    expect((await rejects(fetchSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: mock(() => new Response("x".repeat(4 * 1024 * 1024 + 1))).fetch }))).message).toMatch(/too large/);
    expect((await rejects(fetchSecrets({ host: "https://dp.example.com", token: "", fetch: mock().fetch }))).message).toMatch(/token/);
    expect((await rejects(fetchSecrets({ host: "http://dp.example.com", token: "dps_x" }))).message).toMatch(/https/);
  });

  it("loadSecrets copies into an env object without overriding by default", async () => {
    const f = () => mock(() => Response.json({ secrets: { A: "new", B: "b" } })).fetch;
    const env: Record<string, string | undefined> = { A: "old" };
    const r = await loadSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: f(), env });
    expect(env).toEqual({ A: "old", B: "b" });
    expect(r.loaded).toEqual(["B"]);
    expect(r.skipped).toEqual(["A"]);
    await loadSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: f(), env, override: true });
    expect(env.A).toBe("new");
    const key = "DAYWALKER_SDK_TEST_SECRET";
    await loadSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: mock(() => Response.json({ secrets: { [key]: "1" } })).fetch });
    expect(process.env[key]).toBe("1");
    delete process.env[key];
    const saved = globalThis.process;
    try {
      Object.defineProperty(globalThis, "process", { value: undefined, configurable: true, writable: true });
      expect((await rejects(loadSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: f() }))).message).toMatch(/No environment/);
    } finally {
      Object.defineProperty(globalThis, "process", { value: saved, configurable: true, writable: true });
    }
  });
});

describe("oncall", () => {
  it("triggers, acknowledges and resolves with the routing key in the body", async () => {
    const m = mock((_u, init) => Response.json({ status: "success", message: "Event processed", dedup_key: JSON.parse(init.body as string).dedup_key ?? "gen-1" }, { status: 202 }));
    const oc = createOncall({ host: "https://dp.example.com", routingKey: "rk_0123456789", fetch: m.fetch });
    const t = await oc.trigger({ summary: "Disk full", severity: "critical", source: "db-1", customDetails: { pct: 99 }, links: [{ href: "https://x.example" }] });
    expect(t.dedupKey).toBe("gen-1");
    await oc.acknowledge("gen-1");
    expect((await oc.resolve("gen-1")).status).toBe("success");
    const bodies = m.calls.map((c) => JSON.parse(c.init.body as string));
    expect(m.calls[0]!.url).toBe("https://dp.example.com/oncall/v2/enqueue");
    expect(bodies[0]).toEqual({ routing_key: "rk_0123456789", event_action: "trigger", payload: { summary: "Disk full", severity: "critical", source: "db-1", custom_details: { pct: 99 } }, links: [{ href: "https://x.example" }] });
    expect(bodies[2]).toEqual({ routing_key: "rk_0123456789", event_action: "resolve", dedup_key: "gen-1" });
    expect(JSON.stringify(oc)).not.toMatch(/rk_/);
  });

  it("defaults, validation and errors", async () => {
    const m = mock(() => new Response("", { status: 202 }));
    const oc = createOncall({ host: "https://dp.example.com", routingKey: "rk_0123456789", fetch: m.fetch });
    const r = await oc.trigger({ summary: "x", dedupKey: "k" });
    expect(r).toEqual({ status: "success", message: "", dedupKey: "k" });
    expect(JSON.parse(m.calls[0]!.init.body as string).payload.severity).toBe("error");
    expect(() => oc.trigger({ summary: "" })).toThrow();
    expect(() => oc.acknowledge("")).toThrow();
    expect(() => oc.resolve("")).toThrow();
    expect((await rejects(oc.trigger({ summary: "x", customDetails: { big: "a".repeat(600 * 1024) } }))).message).toMatch(/512 KB/);
    const bad = createOncall({ host: "https://dp.example.com", routingKey: "rk", fetch: mock(() => Response.json({ status: "invalid event" }, { status: 400 })).fetch });
    expect(((await rejects(bad.resolve("k"))) as DevPulseHttpError).status).toBe(400);
    expect(() => createOncall({ host: "https://dp.example.com", routingKey: "" })).toThrow();
  });
});

describe("slo and deploys", () => {
  const api = (fail?: (n: number) => boolean) => {
    const calls: { path: string; body: unknown }[] = [];
    return {
      calls,
      post: (async (path: string, body?: unknown) => {
        calls.push({ path, body });
        if (fail?.(calls.length)) throw new Error("network");
        return { status: 202, data: { accepted: 1 }, headers: new Headers(), etag: null, rateLimit: {}, next: null };
      }) as never,
    };
  };

  it("aggregates per minute and sends each batch once", async () => {
    const a = api();
    let t = Date.UTC(2026, 9, 19, 12, 0, 10);
    const slo = createSloReporter({ api: a, project: "web app", slo: "checkout", flushIntervalMs: 0, now: () => t });
    slo.observe(true);
    slo.observe(false);
    slo.record(5, 5);
    slo.record(0, 0);
    t += 60_000;
    slo.record(1, 2);
    slo.observe(true, new Date(Date.UTC(2026, 9, 19, 11, 0)));
    await slo.flush();
    expect(a.calls[0]!.path).toBe("/api/v1/projects/web%20app/slos/checkout/events");
    expect(a.calls[0]!.body).toEqual({ events: [
      { good: 1, total: 1, timestamp: "2026-10-19T11:00:00.000Z" },
      { good: 6, total: 7, timestamp: "2026-10-19T12:00:00.000Z" },
      { good: 1, total: 2, timestamp: "2026-10-19T12:01:00.000Z" },
    ] });
    await slo.flush();
    expect(a.calls.length).toBe(1);
    expect(() => slo.record(2, 1)).toThrow();
    expect(() => slo.record(1.5, 2)).toThrow();
  });

  it("splits large flushes, reports failures without resending, and runs a timer", async () => {
    const a = api((n) => n === 1);
    const failed: number[] = [];
    let t = 0;
    const slo = createSloReporter({ api: a, project: "p", slo: "s", flushIntervalMs: 0, now: () => t, onError: (_e, ev) => failed.push(ev.length) });
    for (let i = 0; i < MAX_SLO_EVENTS + 5; i++) {
      t = i * 60_000;
      slo.observe(true);
    }
    await slo.shutdown();
    expect(a.calls.length).toBe(2);
    expect(failed).toEqual([MAX_SLO_EVENTS]);
    const b = api();
    const timed = createSloReporter({ api: b, project: "p", slo: "s", flushIntervalMs: 5 });
    timed.observe(true);
    await new Promise((r) => setTimeout(r, 30));
    await timed.shutdown();
    expect(b.calls.length).toBe(1);
    createSloReporter({ api: api(), project: "p", slo: "s" }).shutdown();
    expect(() => createSloReporter({ api: api(), project: "", slo: "s" })).toThrow();
    expect(() => createSloReporter({ api: undefined as never, project: "p", slo: "s" })).toThrow();
  });

  it("pushSloEvents sends once and validates the count", async () => {
    const a = api();
    expect(await pushSloEvents(a, "p", "s", { good: 1, total: 1 })).toEqual({ accepted: 1 });
    expect(a.calls[0]!.body).toEqual({ events: [{ good: 1, total: 1 }] });
    expect((await rejects(pushSloEvents(a, "p", "s", []))).message).toMatch(/1 to/);
  });

  it("recordDeploy posts the marker", async () => {
    const a = api();
    await recordDeploy(a, "web", { environment: "production", sha: "abc", deployedAt: new Date(Date.UTC(2026, 0, 1)) });
    await recordDeploy(a, "web", { environment: "staging", deployedAt: "2026-01-02T00:00:00Z" });
    expect(a.calls[0]).toEqual({ path: "/api/v1/projects/web/deploys", body: { environment: "production", sha: "abc", deployedAt: "2026-01-01T00:00:00.000Z" } });
    expect((a.calls[1]!.body as { deployedAt: string }).deployedAt).toBe("2026-01-02T00:00:00Z");
    expect((await rejects(recordDeploy(a, "", { environment: "x" }))).message).toMatch(/project/);
    expect((await rejects(recordDeploy(a, "web", { environment: "" }))).message).toMatch(/environment/);
  });
});

describe("hardening", () => {
  const unhandled = async (run: () => Promise<void>) => {
    const seen: unknown[] = [];
    const on = (r: unknown) => void seen.push(r);
    process.on("unhandledRejection", on);
    try {
      await run();
      await new Promise((r) => setTimeout(r, 20));
    } finally {
      process.off("unhandledRejection", on);
    }
    return seen;
  };

  it("cron keeps the ping token out of util.inspect", async () => {
    const { inspect } = await import("node:util");
    const cron = createCronMonitor({ pingUrl: "https://dp.example.com/ping/tok_SECRET", fetch: mock().fetch, timeoutMs: 5 });
    expect(inspect(cron, { depth: 5 })).not.toMatch(/tok_SECRET/);
  });

  it("oncall enforces the 512 KB limit in bytes, not UTF-16 units", async () => {
    const m = mock(() => new Response("", { status: 202 }));
    const oc = createOncall({ host: "https://dp.example.com", routingKey: "rk", fetch: m.fetch });
    expect((await rejects(oc.trigger({ summary: "x", customDetails: { big: "é".repeat(300 * 1024) } }))).message).toMatch(/512 KB/);
    expect(m.calls).toHaveLength(0);
  });

  it("logs: a throwing onError in a background flush is not an unhandled rejection", async () => {
    const m = mock(() => new Response("bad", { status: 400 }));
    let errors = 0;
    const seen = await unhandled(async () => {
      const log = createLogger({ host: "https://dp.example.com", token: "dpl_x", fetch: m.fetch, flushIntervalMs: 5, flushAt: 1, onError: () => {
        errors++;
        throw new Error("boom");
      } });
      log.info("a");
      await new Promise((r) => setTimeout(r, 30));
      log.info("b");
      await rejects(log.shutdown());
    });
    expect(errors >= 2).toBe(true);
    expect(seen).toEqual([]);
  });

  it("secrets: invalid JSON errors never quote the response body", async () => {
    const m = mock(() => new Response('{"secrets":{"DB_PASSWORD":"hunter2-very-secret"'));
    const err = await rejects(fetchSecrets({ host: "https://dp.example.com", token: "dps_abc", fetch: m.fetch }));
    expect(err.message).toBe("Secrets response is not valid JSON");
    expect(String(err.stack)).not.toMatch(/hunter2/);
  });

  it("parseDotenv: comments after quoted values, empty values and no prototype pollution", () => {
    const out = parseDotenv('A="x y" # note\nB=\nC=3\nD=\'q\' #c\r\n__proto__=p\nconstructor=c\n');
    expect({ ...out }).toEqual({ A: "x y", B: "", C: "3", D: "q", ["__proto__"]: "p", constructor: "c" });
    expect(Object.getPrototypeOf(out)).toBe(null);
    expect(({} as Record<string, unknown>).p).toBeUndefined();
  });

  it("loadSecrets skips __proto__ and treats inherited names as unset", async () => {
    const m = mock(() => new Response('{"secrets":{"__proto__":"x","toString":"t","A":"1"}}'));
    const env: Record<string, string | undefined> = {};
    const r = await loadSecrets({ host: "https://dp.example.com", token: "dps_abc", fetch: m.fetch, env });
    expect(r.skipped).toEqual(["__proto__"]);
    expect(r.loaded).toEqual(["toString", "A"]);
    expect(Object.getPrototypeOf(env)).toBe(Object.prototype);
    expect(env.A).toBe("1");
    expect(env.toString).toBe("t");
  });

  it("slo: rejects invalid dates and survives a throwing onError on the timer", async () => {
    const slo0 = createSloReporter({ api: { post: (async () => ({})) as never }, project: "p", slo: "s", flushIntervalMs: 0 });
    expect(() => slo0.record(1, 1, new Date("nope"))).toThrow(/valid Date/);
    let errors = 0;
    const seen = await unhandled(async () => {
      const slo = createSloReporter({
        api: { post: (async () => {
          throw new Error("network");
        }) as never },
        project: "p",
        slo: "s",
        flushIntervalMs: 5,
        onError: () => {
          errors++;
          throw new Error("boom");
        },
      });
      slo.observe(true);
      await new Promise((r) => setTimeout(r, 30));
      await slo.shutdown();
    });
    expect(errors).toBe(1);
    expect(seen).toEqual([]);
  });
});
