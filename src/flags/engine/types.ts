/** JSON-compatible flag values. */
export type FlagValue = boolean | string | number | null | FlagValue[] | { [key: string]: FlagValue };

export const OPERATORS = [
  "in",
  "endsWith",
  "startsWith",
  "matches",
  "contains",
  "lessThan",
  "lessThanOrEqual",
  "greaterThan",
  "greaterThanOrEqual",
  "before",
  "after",
  "semVerEqual",
  "semVerLessThan",
  "semVerGreaterThan",
  "segmentMatch",
] as const;
export type Operator = (typeof OPERATORS)[number];

export interface Clause {
  /** Context kind the attribute belongs to. Defaults to "user". */
  contextKind?: string;
  /** Attribute name, or an RFC 6901 JSON Pointer when it starts with "/". */
  attribute: string;
  op: Operator;
  values: FlagValue[];
  negate?: boolean;
}

export interface WeightedVariation {
  variation: number;
  /** 0..100000 (thousandths of a percent). */
  weight: number;
  /** Excluded from experiment analysis even inside an experiment rollout. */
  untracked?: boolean;
}

export interface Rollout {
  kind?: "rollout" | "experiment";
  contextKind?: string;
  bucketBy?: string;
  /** Experiments use a fixed seed so re-running a flag config keeps buckets stable. */
  seed?: number;
  variations: WeightedVariation[];
}

/** A variation index or a rollout. */
export interface VariationOrRollout {
  variation?: number;
  rollout?: Rollout;
}

export interface Rule extends VariationOrRollout {
  id: string;
  description?: string;
  clauses: Clause[];
  trackEvents?: boolean;
}

export interface Target {
  contextKind?: string;
  variation: number;
  values: string[];
}

export interface Prerequisite {
  key: string;
  variation: number;
}

/** A flag as evaluated in one environment. */
export interface FlagConfig {
  key: string;
  version: number;
  on: boolean;
  salt: string;
  variations: FlagValue[];
  offVariation: number | null;
  fallthrough: VariationOrRollout;
  targets: Target[];
  rules: Rule[];
  prerequisites: Prerequisite[];
  clientSide?: boolean;
  trackEvents?: boolean;
  trackEventsFallthrough?: boolean;
  deleted?: boolean;
}

export interface SegmentRule {
  id: string;
  clauses: Clause[];
  /** Optional: include only this fraction of matching contexts (0..100000). */
  weight?: number;
  rolloutContextKind?: string;
  bucketBy?: string;
}

export interface SegmentConfig {
  key: string;
  version: number;
  salt: string;
  included: Target[] | { contextKind?: string; values: string[] }[];
  excluded: { contextKind?: string; values: string[] }[];
  rules: SegmentRule[];
  deleted?: boolean;
}

export type ErrorKind = "FLAG_NOT_FOUND" | "MALFORMED_FLAG" | "USER_NOT_SPECIFIED" | "WRONG_TYPE" | "CLIENT_NOT_READY" | "EXCEPTION";

export type EvaluationReason =
  | { kind: "OFF" }
  | { kind: "FALLTHROUGH"; inExperiment?: boolean }
  | { kind: "TARGET_MATCH" }
  | { kind: "RULE_MATCH"; ruleIndex: number; ruleId: string; inExperiment?: boolean }
  | { kind: "PREREQUISITE_FAILED"; prerequisiteKey: string }
  | { kind: "ERROR"; errorKind: ErrorKind };

export interface EvaluationDetail<T = FlagValue> {
  value: T;
  variationIndex: number | null;
  reason: EvaluationReason;
}

/** Read-only access to flags and segments for one environment. */
export interface DataStore {
  getFlag(key: string): FlagConfig | undefined;
  getSegment(key: string): SegmentConfig | undefined;
}
