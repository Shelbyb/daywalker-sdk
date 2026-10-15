import { RE2JS } from "re2js";
import { compareSemVer, parseSemVer } from "./semver.js";
import type { FlagValue, Operator } from "./types.js";

/** `matches` limits: longer inputs or patterns never match (same limits as the DevPulse server). */
export const MAX_MATCH_INPUT_LENGTH = 1024;
export const MAX_MATCH_PATTERN_LENGTH = 500;
/** Server-parity aliases (`@devpulse/flag-engine` names). */
export const MAX_PATTERN_LENGTH = MAX_MATCH_PATTERN_LENGTH;
export const MAX_MATCH_INPUT = MAX_MATCH_INPUT_LENGTH;

/** A compiled user pattern: only `test()` is exposed. */
export type SafeRegex = { test(input: string): boolean };

const regexCache = new Map<string, SafeRegex | null>();

/**
 * Compile a user-supplied pattern with RE2 (linear-time matching, no backtracking), so no
 * pattern can stall the process however it's written (ReDoS), and every SDK agrees with the
 * DevPulse server on what matches. RE2 has no backreferences or lookaround; patterns using
 * them don't compile and return null (never match).
 */
export function compilePattern(pattern: string): SafeRegex | null {
  if (!regexCache.has(pattern)) {
    let re: SafeRegex | null = null;
    if (pattern.length <= MAX_MATCH_PATTERN_LENGTH) {
      try {
        re = RE2JS.compile(pattern);
      } catch {
        re = null;
      }
    }
    if (regexCache.size > 1000) regexCache.clear();
    regexCache.set(pattern, re);
  }
  return regexCache.get(pattern)!;
}

/** Whether a `matches` pattern is accepted: bounded length and valid RE2 syntax. */
export function isSafePattern(pattern: string): boolean {
  return compilePattern(pattern) !== null;
}

/**
 * @deprecated No longer used: `matches` runs on RE2, which is immune to ReDoS. Kept for
 * backwards compatibility. Conservative heuristic for a group that contains a quantifier or
 * alternation and is itself repeated (`(a+)+`, `(a|aa)+`, `(a+){2,}`).
 */
export function hasNestedQuantifier(pattern: string): boolean {
  const stack: boolean[] = []; // per open group: contains a quantifier / alternation
  for (let i = 0; i < pattern.length; i++) {
    const ch = pattern[i];
    if (ch === "\\") {
      i++;
    } else if (ch === "[") {
      for (i++; i < pattern.length && pattern[i] !== "]"; i++) if (pattern[i] === "\\") i++;
    } else if (ch === "(") {
      stack.push(false);
      if (pattern[i + 1] === "?") i++; // group modifier, not a quantifier
    } else if (ch === ")") {
      const risky = stack.pop() ?? false;
      const next = pattern[i + 1];
      const repeated = next === "*" || next === "+" || next === "{";
      if (risky && repeated) return true;
      if ((risky || repeated) && stack.length) stack[stack.length - 1] = true;
    } else if ((ch === "*" || ch === "+" || ch === "?" || ch === "{" || ch === "|") && stack.length) {
      stack[stack.length - 1] = true;
    }
  }
  return false;
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
      if (typeof actual !== "string" || typeof expected !== "string" || actual.length > MAX_MATCH_INPUT_LENGTH) return false;
      return compilePattern(expected)?.test(actual) ?? false;
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
