import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { SDK_VERSION, init } from "../src/flags/node.js";
import type { ClientOptions } from "../src/flags/client.js";

const flag = (key: string, on: boolean, clientSide = false) => ({
  key,
  version: 1,
  on,
  salt: "s",
  variations: [true, false],
  offVariation: 1,
  fallthrough: { variation: 0 },
  targets: [],
  rules: [{ id: "r", clauses: [{ attribute: "plan", op: "in" as const, values: ["free"] }], variation: 1 }],
  prerequisites: [],
  clientSide,
});

describe("DevPulseNodeClient", () => {
  it("evaluates locally from initial data", async () => {
    const client = init("sdk_test", { baseUrl: "http://unused", initialData: { flags: { a: flag("a", true, true), b: flag("b", false) } } });
    await client.waitForInitialization();
    expect(await client.variation("a", { key: "u", plan: "pro" }, false)).toBe(true);
    expect(await client.variation("a", { key: "u", plan: "free" }, true)).toBe(false);
    expect((await client.variationDetail("b", { key: "u" }, true)).reason).toEqual({ kind: "OFF" });
    expect((await client.variationDetail("missing", { key: "u" }, "d")).value).toBe("d");
    const state = await client.allFlagsState({ key: "u" }, { clientSideOnly: true });
    expect(Object.keys(state.toJSON())).toEqual(["a"]);
    await client.close();
  });

  it("computes secure mode hashes as HMAC-SHA256(sdkKey, canonicalKey)", () => {
    const client = init("sdk_secret", { baseUrl: "http://unused", offline: true });
    expect(client.secureModeHash({ key: "u1" })).toBe(createHmac("sha256", "sdk_secret").update("u1").digest("hex"));
    expect(client.secureModeHash({ kind: "multi", user: { key: "u" }, org: { key: "o" } })).toBe(createHmac("sha256", "sdk_secret").update("org:o:user:u").digest("hex"));
  });

  it("returns defaults when offline", async () => {
    const client = init("k", { baseUrl: "http://unused", offline: true });
    expect(await client.variation("anything", { key: "u" }, 42)).toBe(42);
  });

  it("allFlagsState exposes only client-side flags by default; clientSideOnly: false includes all", async () => {
    const deleted = { ...flag("gone", true, true), deleted: true };
    const exp = { ...flag("exp", true, true), trackEvents: true, fallthrough: { rollout: { kind: "experiment" as const, seed: 1, variations: [{ variation: 0, weight: 100000 }] } } };
    const client = init("sdk_test", { baseUrl: "http://unused", initialData: { flags: { a: flag("a", true, true), secret: flag("secret", true), gone: deleted, exp } } });
    const state = await client.allFlagsState({ key: "u", plan: "pro" });
    expect(state.valid).toBe(true);
    expect(Object.keys(state.toJSON()).sort()).toEqual(["a", "exp"]);
    // Same shape as the client endpoint: reasons/trackEvents for experiments.
    expect(state.toJSON().exp).toEqual({ value: true, variation: 0, version: 1, reason: { kind: "FALLTHROUGH", inExperiment: true }, trackEvents: true, trackReason: true });
    expect(state.toJSON().a).toEqual({ value: true, variation: 0, version: 1 });
    const all = await client.allFlagsState({ key: "u" }, { clientSideOnly: false, withReasons: true });
    expect(Object.keys(all.toJSON()).sort()).toEqual(["a", "exp", "secret"]);
    expect(all.toJSON().secret?.reason).toEqual({ kind: "FALLTHROUGH" });
    // Type-level: toJSON() is directly usable as the browser bootstrap.
    const bootstrap: ClientOptions["bootstrap"] = state.toJSON();
    expect(!!bootstrap).toBe(true);
    await client.close();
  });

  it("clears the waitForInitialization timeout once ready", async () => {
    const client = init("k", { baseUrl: "http://unused", offline: true });
    const before = process.getActiveResourcesInfo().filter((r) => r === "Timeout").length;
    await client.waitForInitialization({ timeoutMs: 60_000 });
    expect(process.getActiveResourcesInfo().filter((r) => r === "Timeout").length).toBe(before);
  });

  it("rejects after the timeout, and sends its real version in the user agent", async () => {
    const agents: string[] = [];
    const f = (async (_u: string, init: { headers: Record<string, string> }) => {
      agents.push(init.headers["user-agent"]!);
      throw new TypeError("refused");
    }) as unknown as typeof fetch;
    const client = init("k", { baseUrl: "http://localhost:1", sendEvents: false, fetch: f });
    let err: Error | undefined;
    await client.waitForInitialization({ timeoutMs: 50 }).catch((e: Error) => (err = e));
    expect(err?.message).toMatch(/timed out/);
    expect(agents[0]).toBe(`DevPulseNode/${SDK_VERSION}`);
    expect(SDK_VERSION).toBe("0.4.0");
    await client.close();
  });

  it("emits stale on a stream error after init and recovered on reconnect", async () => {
    let n = 0;
    const encoder = new TextEncoder();
    const put = `event: put\ndata: ${JSON.stringify({ path: "/", data: { flags: { a: flag("a", true) }, segments: {} } })}\n\n`;
    const f = (async () => {
      n++;
      return new Response(new ReadableStream<Uint8Array>({ start: (c) => { c.enqueue(encoder.encode(put)); if (n === 1) c.close(); } }));
    }) as unknown as typeof fetch;
    const client = init("k", { baseUrl: "http://localhost:1", sendEvents: false, fetch: f });
    const seen: string[] = [];
    client.on("stale", () => seen.push("stale")).on("recovered", () => seen.push("recovered"));
    await client.waitForInitialization({ timeoutMs: 1000 });
    await new Promise((r) => setTimeout(r, 1200));
    expect(seen).toEqual(["stale", "recovered"]);
    await client.close();
  });
});
