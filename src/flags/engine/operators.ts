import { compareSemVer, parseSemVer } from "./semver.js";
import type { FlagValue, Operator } from "./types.js";

const regexCache = new Map<string, RegExp | null>();

function regex(pattern: string): RegExp | null {
  if (!regexCache.has(pattern)) {
    let re: RegExp | null = null;
    try {
      re = new RegExp(pattern);
    } catch {
      re = null;
    }
    if (regexCache.size > 1000) regexCache.clear();
    regexCache.set(pattern, re);
  }
  return regexCache.get(pattern)!;
}

/** RFC 3339 timestamp or Unix milliseconds → epoch ms. */
export function parseTime(v: unknown): number | null {
  if (typeof v === "number" && Number.isFinite(v)) return v;
  if (typeof v !== "string") return null;
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/i.test(v)) return null;
  const t = Date.parse(v);
  return Number.isNaN(t) ? null : t;
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  return ka.length === kb.length && ka.every((k) => deepEqual((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

/** Compare one context value with one clause value. Type mismatches never match. */
export function applyOperator(op: Exclude<Operator, "segmentMatch">, actual: unknown, expected: FlagValue): boolean {
  switch (op) {
    case "in":
      return deepEqual(actual, expected);
    case "endsWith":
      return typeof actual === "string" && typeof expected === "string" && actual.endsWith(expected);
    case "startsWith":
      return typeof actual === "string" && typeof expected === "string" && actual.startsWith(expected);
    case "contains":
      return typeof actual === "string" && typeof expected === "string" && actual.includes(expected);
    case "matches": {
      if (typeof actual !== "string" || typeof expected !== "string") return false;
      return regex(expected)?.test(actual) ?? false;
    }
    case "lessThan":
    case "lessThanOrEqual":
    case "greaterThan":
    case "greaterThanOrEqual": {
      if (typeof actual !== "number" || typeof expected !== "number") return false;
      if (op === "lessThan") return actual < expected;
      if (op === "lessThanOrEqual") return actual <= expected;
      if (op === "greaterThan") return actual > expected;
      return actual >= expected;
    }
    case "before":
    case "after": {
      const a = parseTime(actual);
      const e = parseTime(expected);
      if (a === null || e === null) return false;
      return op === "before" ? a < e : a > e;
    }
    case "semVerEqual":
    case "semVerLessThan":
    case "semVerGreaterThan": {
      const a = parseSemVer(actual);
      const e = parseSemVer(expected);
      if (!a || !e) return false;
      const c = compareSemVer(a, e);
      return op === "semVerEqual" ? c === 0 : op === "semVerLessThan" ? c < 0 : c > 0;
    }
  }
}
