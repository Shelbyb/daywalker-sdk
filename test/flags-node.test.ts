import { createHmac } from "node:crypto";
import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { init } from "../src/flags/node.js";

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
});
