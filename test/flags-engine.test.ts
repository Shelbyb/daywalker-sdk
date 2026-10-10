import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { bucketContext, compareSemVer, evaluateFlag, Evaluator, MemoryStore, parseContext, parseSemVer, sha1Hex, type FlagConfig, type SegmentConfig } from "../src/flags/engine/index.js";

function flag(p: Partial<FlagConfig> = {}): FlagConfig {
  return {
    key: "f",
    version: 1,
    on: true,
    salt: "salt",
    variations: [false, true],
    offVariation: 0,
    fallthrough: { variation: 1 },
    targets: [],
    rules: [],
    prerequisites: [],
    ...p,
  };
}
const ev = (f: FlagConfig, ctx: unknown, store = new MemoryStore({ flags: { [f.key]: f } })) => new Evaluator(store).evaluate(f, parseContext(ctx)).detail;

describe("sha1", () => {
  it("matches node:crypto for ASCII, unicode and block boundaries", () => {
    for (const s of ["", "abc", "a".repeat(55), "a".repeat(56), "a".repeat(64), "héllo wörld ✓", "x".repeat(1000)]) {
      expect(sha1Hex(s)).toBe(createHash("sha1").update(s).digest("hex"));
    }
  });
});

describe("bucketing", () => {
  it("matches LaunchDarkly SDK reference values", () => {
    const b = (key: string) => bucketContext(parseContext({ key }), "hashKey", "saltyA", {}).bucket;
    expect(b("userKeyA")).toBeCloseTo(0.42157587, 7);
    expect(b("userKeyB")).toBeCloseTo(0.6708485, 7);
    expect(b("userKeyC")).toBeCloseTo(0.10343106, 7);
  });

  it("buckets integer attributes like their string form and ignores non-integers", () => {
    const ctx = (v: unknown) => parseContext({ key: "k", n: v });
    expect(bucketContext(ctx(33333), "hashKey", "saltyA", { bucketBy: "n" }).bucket).toBe(bucketContext(ctx("33333"), "hashKey", "saltyA", { bucketBy: "n" }).bucket);
    expect(bucketContext(ctx(3.5), "hashKey", "saltyA", { bucketBy: "n" }).bucket).toBe(0);
  });

  it("uses the seed instead of key+salt when provided", () => {
    const ctx = parseContext({ key: "u" });
    expect(bucketContext(ctx, "a", "s1", { seed: 61 }).bucket).toBe(bucketContext(ctx, "b", "s2", { seed: 61 }).bucket);
  });

  it("distributes rollouts close to their weights", () => {
    const f = flag({ fallthrough: { rollout: { variations: [{ variation: 1, weight: 30000 }, { variation: 0, weight: 70000 }] } } });
    let on = 0;
    for (let i = 0; i < 5000; i++) if (ev(f, { key: `u${i}` }).value === true) on++;
    expect(on / 5000).toBeGreaterThan(0.27);
    expect(on / 5000).toBeLessThan(0.33);
  });
});

describe("semver", () => {
  it("orders per SemVer 2.0.0 §11", () => {
    const order = ["1.0.0-alpha", "1.0.0-alpha.1", "1.0.0-alpha.beta", "1.0.0-beta", "1.0.0-beta.2", "1.0.0-beta.11", "1.0.0-rc.1", "1.0.0", "2", "2.1", "2.1.1"];
    for (let i = 1; i < order.length; i++) expect(compareSemVer(parseSemVer(order[i - 1])!, parseSemVer(order[i])!)).toBe(-1);
    expect(compareSemVer(parseSemVer("1.0.0+build.1")!, parseSemVer("1.0.0")!)).toBe(0);
    expect(parseSemVer("01.0.0")).toBeNull();
  });
});

describe("contexts", () => {
  it("parses single, legacy and multi-kind contexts", () => {
    expect(parseContext({ key: "u" }).kinds.has("user")).toBe(true);
    const m = parseContext({ kind: "multi", user: { key: "u" }, organization: { key: "o:1" } });
    expect([...m.kinds.keys()].sort()).toEqual(["organization", "user"]);
    expect(m.canonicalKey).toBe("organization:o%3A1:user:u");
    expect(() => parseContext({ kind: "user" })).toThrow();
    expect(() => parseContext({ kind: "multi" })).toThrow();
    expect(() => parseContext({ kind: "bad kind", key: "x" })).toThrow();
  });
});

describe("operators", () => {
  const rule = (attribute: string, op: string, values: unknown[], extra: object = {}) =>
    flag({ fallthrough: { variation: 0 }, rules: [{ id: "r", clauses: [{ attribute, op: op as never, values: values as never, ...extra }], variation: 1 }] });
  const cases: [string, string, unknown[], Record<string, unknown>, boolean][] = [
    ["email", "endsWith", ["@acme.dev"], { email: "a@acme.dev" }, true],
    ["email", "startsWith", ["ada"], { email: "ada@x.io" }, true],
    ["email", "contains", ["acme"], { email: "a@acme.dev" }, true],
    ["email", "matches", ["^a.*\\.dev$"], { email: "a@acme.dev" }, true],
    ["email", "matches", ["(unclosed"], { email: "a" }, false],
    ["plan", "in", ["pro", "team"], { plan: "team" }, true],
    ["age", "in", [21], { age: "21" }, false],
    ["age", "greaterThan", [18], { age: 21 }, true],
    ["age", "greaterThanOrEqual", [21], { age: 21 }, true],
    ["age", "lessThan", [18], { age: 21 }, false],
    ["age", "lessThanOrEqual", [21], { age: 21 }, true],
    ["age", "greaterThan", [18], { age: "21" }, false],
    ["signup", "before", ["2025-01-01T00:00:00Z"], { signup: "2024-06-01T00:00:00Z" }, true],
    ["signup", "after", [1700000000000], { signup: 1800000000000 }, true],
    ["signup", "before", ["2025-01-01"], { signup: "2024-06-01T00:00:00Z" }, false],
    ["version", "semVerGreaterThan", ["2.0.0"], { version: "2.1" }, true],
    ["version", "semVerEqual", ["2.0.0"], { version: "2" }, true],
    ["version", "semVerLessThan", ["2.0.0"], { version: "2.0.0-rc.1" }, true],
    ["groups", "in", ["beta"], { groups: ["alpha", "beta"] }, true],
    ["/address/city", "in", ["Paris"], { address: { city: "Paris" } }, true],
    ["/a~1b", "in", [1], { "a/b": 1 }, true],
  ];
  for (const [attr, op, values, ctx, expected] of cases) {
    it(`${attr} ${op} ${JSON.stringify(values)} on ${JSON.stringify(ctx)} → ${expected}`, () => {
      expect(ev(rule(attr, op, values), { key: "k", ...ctx }).value).toBe(expected);
    });
  }

  it("negates, but a missing attribute never matches", () => {
    expect(ev(rule("country", "in", ["US"], { negate: true }), { key: "k", country: "DE" }).value).toBe(true);
    expect(ev(rule("country", "in", ["US"], { negate: true }), { key: "k", country: "US" }).value).toBe(false);
    expect(ev(rule("country", "in", ["US"], { negate: true }), { key: "k" }).value).toBe(false);
  });

  it("matches the special kind attribute across multi-kind contexts", () => {
    expect(ev(rule("kind", "in", ["organization"]), { kind: "multi", user: { key: "u" }, organization: { key: "o" } }).value).toBe(true);
    expect(ev(rule("kind", "in", ["organization"]), { key: "u" }).value).toBe(false);
  });
});

describe("evaluation order and reasons", () => {
  it("serves the off variation (or null) when off", () => {
    expect(ev(flag({ on: false }), { key: "k" })).toEqual({ value: false, variationIndex: 0, reason: { kind: "OFF" } });
    expect(ev(flag({ on: false, offVariation: null }), { key: "k" })).toEqual({ value: null, variationIndex: null, reason: { kind: "OFF" } });
  });

  it("checks targets by context kind before rules", () => {
    const f = flag({
      fallthrough: { variation: 0 },
      targets: [{ contextKind: "organization", variation: 1, values: ["acme"] }],
      rules: [{ id: "r", clauses: [{ contextKind: "organization", attribute: "key", op: "in", values: ["acme"] }], variation: 0 }],
    });
    expect(ev(f, { kind: "organization", key: "acme" }).reason).toEqual({ kind: "TARGET_MATCH" });
    expect(ev(f, { key: "acme" }).reason).toEqual({ kind: "FALLTHROUGH" });
  });

  it("reports rule index/id and experiment allocation", () => {
    const f = flag({
      rules: [
        { id: "a", clauses: [{ attribute: "plan", op: "in", values: ["free"] }], variation: 0 },
        { id: "b", clauses: [{ attribute: "plan", op: "in", values: ["pro"] }], rollout: { kind: "experiment", seed: 1, variations: [{ variation: 0, weight: 50000 }, { variation: 1, weight: 50000 }] } },
      ],
    });
    expect(ev(f, { key: "k", plan: "pro" }).reason).toMatchObject({ kind: "RULE_MATCH", ruleIndex: 1, ruleId: "b", inExperiment: true });
  });

  it("evaluates prerequisites and fails closed", () => {
    const parent = flag({ key: "parent", variations: ["a", "b"], fallthrough: { variation: 1 } });
    const child = flag({ key: "child", prerequisites: [{ key: "parent", variation: 1 }] });
    const store = new MemoryStore({ flags: { parent, child } });
    const r = new Evaluator(store).evaluate(child, parseContext({ key: "k" }));
    expect(r.detail.value).toBe(true);
    expect(r.prerequisites.map((p) => p.flag.key)).toEqual(["parent"]);
    store.upsert("flag", { ...parent, version: 2, on: false });
    expect(ev(child, { key: "k" }, store).reason).toEqual({ kind: "PREREQUISITE_FAILED", prerequisiteKey: "parent" });
    store.flags.delete("parent");
    expect(ev(child, { key: "k" }, store).reason).toEqual({ kind: "PREREQUISITE_FAILED", prerequisiteKey: "parent" });
  });

  it("detects prerequisite cycles as malformed", () => {
    const a = flag({ key: "a", prerequisites: [{ key: "b", variation: 1 }] });
    const b = flag({ key: "b", prerequisites: [{ key: "a", variation: 1 }] });
    expect(ev(a, { key: "k" }, new MemoryStore({ flags: { a, b } })).reason).toEqual({ kind: "ERROR", errorKind: "MALFORMED_FLAG" });
  });

  it("returns MALFORMED_FLAG for bad variation indexes", () => {
    expect(ev(flag({ fallthrough: { variation: 9 } }), { key: "k" }).reason).toEqual({ kind: "ERROR", errorKind: "MALFORMED_FLAG" });
  });
});

describe("segments", () => {
  const seg = (p: Partial<SegmentConfig> = {}): SegmentConfig => ({ key: "beta", version: 1, salt: "s", included: [], excluded: [], rules: [], ...p });
  const f = flag({ fallthrough: { variation: 0 }, rules: [{ id: "r", clauses: [{ attribute: "segment", op: "segmentMatch", values: ["beta"] }], variation: 1 }] });
  const run = (s: SegmentConfig, ctx: unknown) => ev(f, ctx, new MemoryStore({ flags: { f }, segments: { beta: s } })).value;

  it("includes, excludes and matches rules", () => {
    expect(run(seg({ included: [{ values: ["u1"] }] }), { key: "u1" })).toBe(true);
    const s = seg({ excluded: [{ values: ["u2"] }], rules: [{ id: "x", clauses: [{ attribute: "plan", op: "in", values: ["pro"] }] }] });
    expect(run(s, { key: "u2", plan: "pro" })).toBe(false);
    expect(run(s, { key: "u3", plan: "pro" })).toBe(true);
    expect(run(s, { key: "u3", plan: "free" })).toBe(false);
  });

  it("supports other context kinds and weighted rules", () => {
    expect(run(seg({ included: [{ contextKind: "organization", values: ["acme"] }] }), { kind: "organization", key: "acme" })).toBe(true);
    const half = seg({ rules: [{ id: "w", clauses: [{ attribute: "key", op: "matches", values: [".*"] }], weight: 50000 }] });
    let n = 0;
    for (let i = 0; i < 2000; i++) if (run(half, { key: `u${i}` })) n++;
    expect(n / 2000).toBeGreaterThan(0.45);
    expect(n / 2000).toBeLessThan(0.55);
  });
});

describe("evaluateFlag", () => {
  it("returns defaults with error reasons", () => {
    const store = new MemoryStore({ flags: { f: flag() } });
    expect(evaluateFlag(store, "missing", { key: "k" }, "dflt")).toMatchObject({ value: "dflt", reason: { kind: "ERROR", errorKind: "FLAG_NOT_FOUND" } });
    expect(evaluateFlag(store, "f", { name: "no key" }, false)).toMatchObject({ value: false, reason: { kind: "ERROR", errorKind: "USER_NOT_SPECIFIED" } });
    expect(evaluateFlag(store, "f", { key: "k" }, false).value).toBe(true);
  });
});
