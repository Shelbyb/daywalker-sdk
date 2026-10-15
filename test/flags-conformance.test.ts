import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { applyOperator, compilePattern, evaluateFlag, isSafePattern, MAX_MATCH_INPUT, MAX_MATCH_INPUT_LENGTH, MAX_MATCH_PATTERN_LENGTH, MAX_PATTERN_LENGTH, MemoryStore, type FlagConfig, type FlagValue, type SegmentConfig } from "../src/flags/engine/index.js";

const matches = (pattern: string, input: string) => applyOperator("matches", input, pattern);

describe("matches operator: RE2 parity with the DevPulse server", () => {
  it("accepts repeated groups the old nested-quantifier heuristic rejected", () => {
    expect(matches("^[a-z]+(\\.[a-z]+)*@acme\\.com$", "jane.doe@acme.com")).toBe(true);
    expect(matches("^(foo|bar)+$", "foobar")).toBe(true);
    expect(matches("^(\\d{3})+$", "123456")).toBe(true);
    expect(matches("^(\\d{3})+$", "12345")).toBe(false);
  });

  it("supports inline flags", () => {
    expect(matches("(?i)^ADMIN", "admin-1")).toBe(true);
    expect(matches("^ADMIN", "admin-1")).toBe(false);
  });

  it("never matches lookaround or backreferences (invalid in RE2)", () => {
    expect(matches("^(?!test).*@acme\\.com$", "jane@acme.com")).toBe(false);
    expect(matches("^(?!test).*@acme\\.com$", "test@acme.com")).toBe(false);
    expect(matches("^(a)\\1$", "aa")).toBe(false);
    expect(isSafePattern("^(?!test)")).toBe(false);
    expect(isSafePattern("(?<=a)b")).toBe(false);
    expect(isSafePattern("^(a)\\1$")).toBe(false);
    expect(compilePattern("[unclosed")).toBeNull();
  });

  it("is linear-time on catastrophic-backtracking patterns", () => {
    const input = "a".repeat(1000);
    for (const p of ["^a*a*a*a*b$", "^(a+)+$", "^(a|aa)+b$", "\\w*\\w*\\w*\\w*!", "^(?:a|ab)(?:a|ab)(?:a|ab).*.*.*c$"]) {
      const t = performance.now();
      matches(p, input);
      expect(performance.now() - t).toBeLessThan(200);
    }
    // Nested quantifiers are fine now, and still correct.
    expect(matches("^(a+)+$", input)).toBe(true);
  });

  it("keeps the server's pattern and input limits", () => {
    expect(MAX_PATTERN_LENGTH).toBe(500);
    expect(MAX_MATCH_INPUT).toBe(1024);
    expect(MAX_MATCH_PATTERN_LENGTH).toBe(MAX_PATTERN_LENGTH);
    expect(MAX_MATCH_INPUT_LENGTH).toBe(MAX_MATCH_INPUT);
    expect(isSafePattern("a".repeat(500))).toBe(true);
    expect(isSafePattern("a".repeat(501))).toBe(false);
    expect(matches("^a+$", "a".repeat(1024))).toBe(true);
    expect(matches("^a+$", "a".repeat(1025))).toBe(false);
  });

  it("finds a match anywhere unless anchored, like RegExp#test", () => {
    expect(matches("acme", "jane@acme.com")).toBe(true);
    expect(matches("^acme", "jane@acme.com")).toBe(false);
  });
});

type Vectors = {
  flags: Record<string, FlagConfig>;
  segments: Record<string, SegmentConfig>;
  cases: { name: string; flag: string; context: unknown; default: FlagValue; expect: { value: FlagValue; variationIndex: number | null; reason: unknown } }[];
};

describe("shared evaluation vectors (test-vectors/flags-eval.json)", () => {
  const vectors = JSON.parse(readFileSync(new URL("../test-vectors/flags-eval.json", import.meta.url), "utf8")) as Vectors;
  const store = new MemoryStore({ flags: vectors.flags, segments: vectors.segments });
  it("has cases", () => expect(vectors.cases.length).toBeGreaterThan(20));
  for (const c of vectors.cases) {
    it(c.name, () => {
      const { prerequisites: _, ...detail } = evaluateFlag(store, c.flag, c.context, c.default);
      expect(detail).toEqual(c.expect);
    });
  }
});
