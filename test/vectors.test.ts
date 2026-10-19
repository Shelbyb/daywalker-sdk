import { createHash, createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { applyOperator, bucketContext, parseContext } from "../src/flags/engine/index.js";
import { hmacSha256Hex } from "../src/flags/common/hmac.js";

const load = <T>(f: string) => JSON.parse(readFileSync(new URL(`../test-vectors/${f}`, import.meta.url), "utf8")) as T;

describe("language-neutral vectors", () => {
  it("flags-bucketing.json: sha1 prefix / 0xFFFFFFFFFFFFFFF", () => {
    const v = load<{ cases: { flagKey: string; salt: string; key: string; seed?: number; input: string; sha1: string; bucket: number }[] }>("flags-bucketing.json");
    expect(v.cases.length).toBeGreaterThan(8);
    for (const c of v.cases) {
      expect(c.input).toBe(c.seed !== undefined ? `${c.seed}.${c.key}` : `${c.flagKey}.${c.salt}.${c.key}`);
      expect(createHash("sha1").update(c.input).digest("hex")).toBe(c.sha1);
      // Independent of the SDK: BigInt keeps all 60 bits, then one float64 division.
      const exact = Number(BigInt("0x" + c.sha1.slice(0, 15))) / 0xfffffffffffffff;
      expect(Math.abs(exact - c.bucket)).toBeLessThan(1e-12);
      const { bucket } = bucketContext(parseContext({ key: c.key }), c.flagKey, c.salt, { seed: c.seed });
      expect(bucket).toBe(c.bucket);
    }
  });

  it("flags-context.json: canonical keys and invalid contexts", () => {
    const v = load<{ cases: { context: unknown; canonicalKey?: string; error?: boolean }[] }>("flags-context.json");
    for (const c of v.cases) {
      if (c.error) expect(() => parseContext(c.context)).toThrow();
      else expect(parseContext(c.context).canonicalKey).toBe(c.canonicalKey);
    }
    expect(v.cases.some((c) => c.error)).toBe(true);
  });

  it("secure-mode-hash.json: HMAC-SHA256 hex, both portable and node:crypto", () => {
    const v = load<{ cases: { sdkKey: string; canonicalKey: string; hash: string }[] }>("secure-mode-hash.json");
    expect(v.cases.length).toBeGreaterThan(5);
    for (const c of v.cases) {
      expect(createHmac("sha256", c.sdkKey).update(c.canonicalKey).digest("hex")).toBe(c.hash);
      expect(hmacSha256Hex(c.sdkKey, c.canonicalKey)).toBe(c.hash);
    }
  });

  it("flags-operators.json: every operator", () => {
    const v = load<{ cases: { op: string; actual: unknown; expected: unknown; result: boolean }[] }>("flags-operators.json");
    expect(new Set(v.cases.map((c) => c.op)).size).toBe(14);
    for (const c of v.cases) expect(applyOperator(c.op as never, c.actual, c.expected as never)).toBe(c.result);
  });
});
