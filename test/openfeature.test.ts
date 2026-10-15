import { describe, it } from "node:test";
import { ProviderEvents as ServerEvents } from "@openfeature/server-sdk";
import { ProviderEvents as WebEvents } from "@openfeature/web-sdk";
import { expect } from "./helpers/expect.js";
import { init } from "../src/flags/node.js";
import { DevPulseServerProvider } from "../src/openfeature/server.js";
import { DevPulseWebProvider } from "../src/openfeature/web.js";
import { toDevPulseContext } from "../src/openfeature/shared.js";

const promo = {
  key: "promo",
  version: 1,
  on: true,
  salt: "s",
  variations: [false, true],
  offVariation: 0,
  fallthrough: { variation: 0 },
  targets: [],
  prerequisites: [],
  rules: [{ id: "r1", variation: 1, clauses: [{ attribute: "signupDate", op: "after" as const, values: ["2024-01-01T00:00:00Z"] }] }],
};
const logger = { error() {}, warn() {}, info() {}, debug() {} };

describe("toDevPulseContext", () => {
  it("turns Dates into ISO strings at any depth", () => {
    const d = new Date("2025-06-01T00:00:00Z");
    expect(toDevPulseContext({ targetingKey: "u1", signupDate: d, nested: { at: d, list: [d, 1] }, bad: new Date("nope") })).toEqual({
      kind: "user",
      key: "u1",
      signupDate: "2025-06-01T00:00:00.000Z",
      nested: { at: "2025-06-01T00:00:00.000Z", list: ["2025-06-01T00:00:00.000Z", 1] },
    });
    expect(toDevPulseContext({ kind: "multi", user: { key: "u", since: d } } as never)).toEqual({ kind: "multi", user: { key: "u", since: "2025-06-01T00:00:00.000Z" } });
  });
});

describe("DevPulseServerProvider", () => {
  it("matches date rules for Date values in the evaluation context", async () => {
    const client = init("sdk", { baseUrl: "http://localhost", initialData: { flags: { promo } } });
    const provider = new DevPulseServerProvider(client);
    await provider.initialize();
    const d = await provider.resolveBooleanEvaluation("promo", false, { targetingKey: "u1", signupDate: new Date("2025-06-01T00:00:00Z") }, logger);
    expect(d).toMatchObject({ value: true, reason: "TARGETING_MATCH" });
    const old = await provider.resolveBooleanEvaluation("promo", false, { targetingKey: "u1", signupDate: new Date("2023-06-01T00:00:00Z") }, logger);
    expect(old).toMatchObject({ value: false, reason: "DEFAULT" });
  });

  it("doesn't close an injected client, and detaches from it", async () => {
    const client = init("sdk", { baseUrl: "http://localhost", initialData: { flags: { promo } } });
    let closed = false;
    const close = client.close.bind(client);
    client.close = async () => {
      closed = true;
      await close();
    };
    const provider = new DevPulseServerProvider(client);
    expect(client.listenerCount("update")).toBe(1);
    await provider.onClose();
    expect(closed).toBe(false);
    expect(client.listenerCount("update")).toBe(0);
    expect(client.listenerCount("stale")).toBe(0);
    expect(await client.variation("promo", { key: "u", signupDate: "2025-01-01T00:00:00Z" }, false)).toBe(true);
  });

  it("closes a client it created", async () => {
    const provider = new DevPulseServerProvider("sdk", { baseUrl: "http://localhost", initialData: { flags: { promo } } });
    let closed = false;
    const close = provider.client.close.bind(provider.client);
    provider.client.close = async () => {
      closed = true;
      await close();
    };
    await provider.onClose();
    expect(closed).toBe(true);
  });

  it("emits STALE, READY (recovered) and ERROR from client status", () => {
    const client = init("sdk", { baseUrl: "http://localhost", initialData: { flags: { promo } } });
    const provider = new DevPulseServerProvider(client);
    const seen: string[] = [];
    for (const e of [ServerEvents.Stale, ServerEvents.Ready, ServerEvents.Error]) provider.events.addHandler(e, () => seen.push(e));
    client.emit("stale", new Error("stream lost"));
    client.emit("recovered");
    client.emit("failed", new Error("Invalid SDK key"));
    expect(seen).toEqual([ServerEvents.Stale, ServerEvents.Ready, ServerEvents.Error]);
  });
});

describe("DevPulseWebProvider", () => {
  const fetchFlags = (async (url: string) => {
    const ctx = JSON.parse(Buffer.from(new URL(url).searchParams.get("context")!, "base64url").toString()) as Record<string, unknown>;
    // Echo the context back so the test can see what was sent.
    return Response.json({ seen: { value: JSON.stringify(ctx), variation: 0, version: 1 } });
  }) as unknown as typeof fetch;

  it("sends Dates as ISO strings and emits ERROR/STALE from client status", async () => {
    const provider = new DevPulseWebProvider("cid", { baseUrl: "https://x", streaming: false, sendEvents: false, fetch: fetchFlags });
    await provider.initialize({ targetingKey: "u1", since: new Date("2025-06-01T00:00:00Z") });
    const r = provider.resolveStringEvaluation("seen", "", {}, logger);
    expect(JSON.parse(r.value)).toEqual({ since: "2025-06-01T00:00:00.000Z", kind: "user", key: "u1" });
    const seen: string[] = [];
    for (const e of [WebEvents.Stale, WebEvents.Ready, WebEvents.Error]) provider.events.addHandler(e, () => seen.push(e));
    const client = (provider as unknown as { client: { emit(e: string, ...a: unknown[]): void } }).client;
    client.emit("stale", new Error("lost"));
    client.emit("recovered");
    client.emit("failed", new Error("bad id"));
    expect(seen).toEqual([WebEvents.Stale, WebEvents.Ready, WebEvents.Error]);
    await provider.onClose();
  });

  it("closes the previous client when initialized again", async () => {
    const provider = new DevPulseWebProvider("cid", { baseUrl: "https://x", streaming: false, sendEvents: false, fetch: fetchFlags });
    await provider.initialize({ targetingKey: "a" });
    const first = (provider as unknown as { client: { isClosed: boolean } }).client;
    await provider.initialize({ targetingKey: "b" });
    await new Promise((r) => setTimeout(r, 0));
    expect(first.isClosed).toBe(true);
    await provider.onClose();
  });
});
