import { bucketContext, variationForRollout } from "./bucket.js";
import { ContextError, getAttribute, parseContext, type Context } from "./context.js";
import { applyOperator } from "./operators.js";
import type { Clause, DataStore, EvaluationDetail, EvaluationReason, FlagConfig, FlagValue, SegmentConfig, VariationOrRollout } from "./types.js";

export interface PrerequisiteEvaluation {
  flag: FlagConfig;
  prerequisiteOf: string;
  detail: EvaluationDetail;
}

export interface EvaluationResult {
  detail: EvaluationDetail;
  /** Prerequisite flags evaluated along the way (for analytics events). */
  prerequisites: PrerequisiteEvaluation[];
}

const MAX_SEGMENT_DEPTH = 10;

class MalformedFlag extends Error {}

/**
 * Evaluates flags against contexts. Pure and synchronous: the same inputs
 * always produce the same output on every platform.
 */
export class Evaluator {
  constructor(private readonly store: DataStore) {}

  evaluate(flag: FlagConfig, context: Context): EvaluationResult {
    const prerequisites: PrerequisiteEvaluation[] = [];
    try {
      const detail = this.evalFlag(flag, context, prerequisites, new Set());
      return { detail, prerequisites };
    } catch (err) {
      if (err instanceof MalformedFlag) return { detail: errorDetail("MALFORMED_FLAG"), prerequisites };
      return { detail: errorDetail("EXCEPTION"), prerequisites };
    }
  }

  private evalFlag(flag: FlagConfig, ctx: Context, events: PrerequisiteEvaluation[], visiting: Set<string>): EvaluationDetail {
    if (!flag.on) return this.off(flag, { kind: "OFF" });

    if (visiting.has(flag.key)) throw new MalformedFlag(`Prerequisite cycle at ${flag.key}`);
    visiting.add(flag.key);
    try {
      for (const pre of flag.prerequisites) {
        const preFlag = this.store.getFlag(pre.key);
        if (!preFlag || preFlag.deleted) return this.off(flag, { kind: "PREREQUISITE_FAILED", prerequisiteKey: pre.key });
        const detail = this.evalFlag(preFlag, ctx, events, visiting);
        events.push({ flag: preFlag, prerequisiteOf: flag.key, detail });
        if (!preFlag.on || detail.variationIndex !== pre.variation) {
          return this.off(flag, { kind: "PREREQUISITE_FAILED", prerequisiteKey: pre.key });
        }
      }
    } finally {
      visiting.delete(flag.key);
    }

    for (const target of flag.targets) {
      const single = ctx.kinds.get(target.contextKind ?? "user");
      if (single && target.values.includes(single.key)) return this.variation(flag, target.variation, { kind: "TARGET_MATCH" });
    }

    for (const [ruleIndex, rule] of flag.rules.entries()) {
      if (rule.clauses.every((c) => this.clauseMatches(c, ctx, 0))) {
        return this.serve(flag, rule, ctx, (inExperiment) => ({ kind: "RULE_MATCH", ruleIndex, ruleId: rule.id, ...(inExperiment ? { inExperiment } : {}) }));
      }
    }

    return this.serve(flag, flag.fallthrough, ctx, (inExperiment) => ({ kind: "FALLTHROUGH", ...(inExperiment ? { inExperiment } : {}) }));
  }

  private serve(flag: FlagConfig, vr: VariationOrRollout, ctx: Context, reason: (inExperiment: boolean) => EvaluationReason): EvaluationDetail {
    if (vr.variation !== undefined && vr.variation !== null) return this.variation(flag, vr.variation, reason(false));
    if (vr.rollout) {
      const picked = variationForRollout(ctx, flag.key, flag.salt, vr.rollout);
      if (!picked) throw new MalformedFlag("Empty rollout");
      return this.variation(flag, picked.variation, reason(picked.inExperiment));
    }
    throw new MalformedFlag("Rule has neither variation nor rollout");
  }

  private variation(flag: FlagConfig, index: number, reason: EvaluationReason): EvaluationDetail {
    if (!Number.isInteger(index) || index < 0 || index >= flag.variations.length) throw new MalformedFlag(`Invalid variation ${index}`);
    return { value: flag.variations[index] as FlagValue, variationIndex: index, reason };
  }

  private off(flag: FlagConfig, reason: EvaluationReason): EvaluationDetail {
    if (flag.offVariation === null || flag.offVariation === undefined) return { value: null, variationIndex: null, reason };
    return this.variation(flag, flag.offVariation, reason);
  }

  private clauseMatches(clause: Clause, ctx: Context, depth: number): boolean {
    if (clause.op === "segmentMatch") {
      const matched = clause.values.some((key) => typeof key === "string" && this.segmentMatches(key, ctx, depth));
      return clause.negate ? !matched : matched;
    }
    // The special "kind" attribute matches against every kind in the context.
    if (clause.attribute === "kind") {
      const matched = [...ctx.kinds.keys()].some((k) => clause.values.some((v) => applyOperator(clause.op as never, k, v)));
      return clause.negate ? !matched : matched;
    }
    const single = ctx.kinds.get(clause.contextKind ?? "user");
    if (!single) return false; // missing context kind never matches, even when negated
    const actual = getAttribute(single, clause.attribute);
    if (actual === undefined || actual === null) return false;
    const candidates = Array.isArray(actual) ? actual : [actual];
    const matched = candidates.some((a) => clause.values.some((v) => applyOperator(clause.op as never, a, v)));
    return clause.negate ? !matched : matched;
  }

  private segmentMatches(key: string, ctx: Context, depth: number): boolean {
    if (depth >= MAX_SEGMENT_DEPTH) throw new MalformedFlag("Segment nesting too deep");
    const seg = this.store.getSegment(key);
    if (!seg || seg.deleted) return false;
    const inList = (list: SegmentConfig["included"]) =>
      list.some((t) => {
        const single = ctx.kinds.get(t.contextKind ?? "user");
        return !!single && t.values.includes(single.key);
      });
    if (inList(seg.included)) return true;
    if (inList(seg.excluded)) return false;
    for (const rule of seg.rules) {
      if (!rule.clauses.every((c) => this.clauseMatches(c, ctx, depth + 1))) continue;
      if (rule.weight === undefined || rule.weight === null) return true;
      const { bucket } = bucketContext(ctx, seg.key, seg.salt, { contextKind: rule.rolloutContextKind, bucketBy: rule.bucketBy });
      return bucket < rule.weight / 100000;
    }
    return false;
  }
}

export function errorDetail(errorKind: Extract<EvaluationReason, { kind: "ERROR" }>["errorKind"], value: FlagValue = null): EvaluationDetail {
  return { value, variationIndex: null, reason: { kind: "ERROR", errorKind } };
}

/**
 * Convenience: evaluate a flag by key for raw context input, returning the
 * default value (with an ERROR reason) when anything goes wrong.
 */
export function evaluateFlag<T extends FlagValue>(store: DataStore, flagKey: string, contextInput: unknown, defaultValue: T): EvaluationDetail<T> & { prerequisites: PrerequisiteEvaluation[] } {
  let ctx: Context;
  try {
    ctx = parseContext(contextInput);
  } catch (err) {
    return { ...(errorDetail(err instanceof ContextError ? "USER_NOT_SPECIFIED" : "EXCEPTION", defaultValue) as EvaluationDetail<T>), prerequisites: [] };
  }
  const flag = store.getFlag(flagKey);
  if (!flag || flag.deleted) return { ...(errorDetail("FLAG_NOT_FOUND", defaultValue) as EvaluationDetail<T>), prerequisites: [] };
  const { detail, prerequisites } = new Evaluator(store).evaluate(flag, ctx);
  if (detail.reason.kind === "ERROR" || detail.variationIndex === null) return { ...(detail as EvaluationDetail<T>), value: defaultValue, prerequisites };
  return { ...(detail as EvaluationDetail<T>), prerequisites };
}

/** Plain in-memory store, handy for SDKs and tests. */
export class MemoryStore implements DataStore {
  flags = new Map<string, FlagConfig>();
  segments = new Map<string, SegmentConfig>();
  constructor(data?: { flags?: Record<string, FlagConfig>; segments?: Record<string, SegmentConfig> }) {
    if (data) this.replace(data);
  }
  replace(data: { flags?: Record<string, FlagConfig>; segments?: Record<string, SegmentConfig> }) {
    this.flags = new Map(Object.entries(data.flags ?? {}));
    this.segments = new Map(Object.entries(data.segments ?? {}));
  }
  /** Apply a versioned upsert; stale versions are ignored. Returns true when applied. */
  upsert(kind: "flag" | "segment", item: FlagConfig | SegmentConfig): boolean {
    const map = (kind === "flag" ? this.flags : this.segments) as Map<string, FlagConfig | SegmentConfig>;
    const cur = map.get(item.key);
    if (cur && cur.version >= item.version) return false;
    map.set(item.key, item);
    return true;
  }
  getFlag(key: string) {
    return this.flags.get(key);
  }
  getSegment(key: string) {
    return this.segments.get(key);
  }
}
