/**
 * A small Jest/Vitest-style `expect` over node:assert, so tests run on the
 * built-in node:test runner without extra dependencies.
 */
import assert from "node:assert/strict";

type Matchers = {
  toBe(v: unknown): void;
  toEqual(v: unknown): void;
  toMatchObject(v: object): void;
  toHaveLength(n: number): void;
  toBeNull(): void;
  toBeUndefined(): void;
  toBeGreaterThan(n: number): void;
  toBeLessThan(n: number): void;
  toBeCloseTo(n: number, digits?: number): void;
  toMatch(re: RegExp | string): void;
  toThrow(match?: RegExp | string): void;
};

function matchesObject(actual: unknown, expected: unknown): boolean {
  if (expected === null || typeof expected !== "object") return Object.is(actual, expected) || (actual instanceof Object === false && actual === expected);
  if (actual === null || typeof actual !== "object") return false;
  if (Array.isArray(expected)) return Array.isArray(actual) && actual.length === expected.length && expected.every((e, i) => matchesObject((actual as unknown[])[i], e));
  return Object.entries(expected as Record<string, unknown>).every(([k, v]) => matchesObject((actual as Record<string, unknown>)[k], v));
}

function build(actual: unknown, negate: boolean): Matchers {
  const check = (ok: boolean, message: string) => assert.ok(negate ? !ok : ok, negate ? `not: ${message}` : message);
  const deepEq = (a: unknown, b: unknown) => {
    try {
      assert.deepStrictEqual(normalize(a), normalize(b));
      return true;
    } catch {
      return false;
    }
  };
  return {
    toBe: (v) => check(Object.is(actual, v), `expected ${fmt(actual)} to be ${fmt(v)}`),
    toEqual: (v) => check(deepEq(actual, v), `expected ${fmt(actual)} to equal ${fmt(v)}`),
    toMatchObject: (v) => check(matchesObject(actual, v), `expected ${fmt(actual)} to match ${fmt(v)}`),
    toHaveLength: (n) => check((actual as { length?: number })?.length === n, `expected length ${n}, got ${(actual as { length?: number })?.length}`),
    toBeNull: () => check(actual === null, `expected ${fmt(actual)} to be null`),
    toBeUndefined: () => check(actual === undefined, `expected ${fmt(actual)} to be undefined`),
    toBeGreaterThan: (n) => check((actual as number) > n, `expected ${fmt(actual)} > ${n}`),
    toBeLessThan: (n) => check((actual as number) < n, `expected ${fmt(actual)} < ${n}`),
    toBeCloseTo: (n, digits = 2) => check(Math.abs((actual as number) - n) < 10 ** -digits / 2, `expected ${fmt(actual)} ≈ ${n}`),
    toMatch: (re) => check(typeof actual === "string" && (typeof re === "string" ? actual.includes(re) : re.test(actual)), `expected ${fmt(actual)} to match ${String(re)}`),
    toThrow: (match) => {
      let threw = false;
      let msg = "";
      try {
        (actual as () => unknown)();
      } catch (e) {
        threw = true;
        msg = (e as Error)?.message ?? String(e);
      }
      const ok = threw && (!match || (typeof match === "string" ? msg.includes(match) : match.test(msg)));
      check(ok, `expected function to throw${match ? ` ${String(match)}` : ""}${threw ? `, got "${msg}"` : ""}`);
    },
  };
}

/** `toEqual` ignores undefined properties, like Jest. */
function normalize(v: unknown): unknown {
  if (Array.isArray(v)) return v.map(normalize);
  if (v && typeof v === "object" && Object.getPrototypeOf(v) === Object.prototype) {
    return Object.fromEntries(Object.entries(v).filter(([, x]) => x !== undefined).map(([k, x]) => [k, normalize(x)]));
  }
  return v;
}

const fmt = (v: unknown) => {
  try {
    return typeof v === "string" ? JSON.stringify(v) : JSON.stringify(v) ?? String(v);
  } catch {
    return String(v);
  }
};

export function expect(actual: unknown): Matchers & { not: Matchers } {
  return Object.assign(build(actual, false), { not: build(actual, true) });
}
