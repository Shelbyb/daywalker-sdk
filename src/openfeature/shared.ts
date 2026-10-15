import type { EvaluationContext, ResolutionDetails, ResolutionReason } from "@openfeature/core";
import { ErrorCode, StandardResolutionReasons } from "@openfeature/core";

type Reason = { kind: string; errorKind?: string; inExperiment?: boolean } | null | undefined;
type Detail<T> = { value: T; variationIndex: number | null; reason: Reason };

/**
 * OpenFeature context values may be Dates; DevPulse compares RFC 3339 strings (or epoch ms) for
 * `before`/`after`, so Dates become ISO strings at any depth (invalid Dates are dropped).
 */
function toJsonValue(v: unknown): unknown {
  if (v instanceof Date) return Number.isNaN(v.getTime()) ? undefined : v.toISOString();
  if (Array.isArray(v)) return v.map(toJsonValue);
  if (v && typeof v === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, x] of Object.entries(v)) {
      const j = toJsonValue(x);
      if (j !== undefined) out[k] = j;
    }
    return out;
  }
  return v;
}

/**
 * OpenFeature context → DevPulse context. Dates become ISO 8601 strings. `targetingKey` becomes the key;
 * `kind` selects the context kind (default "user"); multi-kind contexts pass through.
 */
export function toDevPulseContext(ctx: EvaluationContext): Record<string, unknown> {
  const { targetingKey, ...rest } = toJsonValue(ctx) as Record<string, unknown>;
  if (rest.kind === "multi") return rest;
  return { ...rest, kind: typeof rest.kind === "string" ? rest.kind : "user", key: targetingKey ?? rest.key };
}

const ERRORS: Record<string, ErrorCode> = {
  FLAG_NOT_FOUND: ErrorCode.FLAG_NOT_FOUND,
  WRONG_TYPE: ErrorCode.TYPE_MISMATCH,
  USER_NOT_SPECIFIED: ErrorCode.TARGETING_KEY_MISSING,
  CLIENT_NOT_READY: ErrorCode.PROVIDER_NOT_READY,
  MALFORMED_FLAG: ErrorCode.PARSE_ERROR,
};

export function toResolution<T>(detail: Detail<T>): ResolutionDetails<T> {
  const r = detail.reason;
  if (r?.kind === "ERROR") {
    return { value: detail.value, reason: StandardResolutionReasons.ERROR, errorCode: ERRORS[r.errorKind ?? ""] ?? ErrorCode.GENERAL, errorMessage: r.errorKind };
  }
  let reason: ResolutionReason = StandardResolutionReasons.UNKNOWN;
  if (r?.kind === "OFF") reason = StandardResolutionReasons.DISABLED;
  else if (r?.kind === "TARGET_MATCH" || r?.kind === "RULE_MATCH") reason = r.inExperiment ? StandardResolutionReasons.SPLIT : StandardResolutionReasons.TARGETING_MATCH;
  else if (r?.kind === "FALLTHROUGH") reason = r.inExperiment ? StandardResolutionReasons.SPLIT : StandardResolutionReasons.DEFAULT;
  else if (r?.kind === "PREREQUISITE_FAILED") reason = StandardResolutionReasons.DISABLED;
  return { value: detail.value, reason, ...(detail.variationIndex !== null ? { variant: String(detail.variationIndex) } : {}), flagMetadata: r ? { devpulseReason: r.kind } : {} };
}

export function typeCheck<T>(detail: Detail<unknown>, expected: string, defaultValue: T): Detail<T> {
  const actual = Array.isArray(detail.value) ? "object" : typeof detail.value;
  if (detail.reason?.kind !== "ERROR" && actual !== expected) return { value: defaultValue, variationIndex: null, reason: { kind: "ERROR", errorKind: "WRONG_TYPE" } };
  return detail as Detail<T>;
}
