import type { FlagValue } from "./types.js";

/**
 * Evaluation contexts. Either a single-kind context
 *   { kind: "user", key: "u1", email: "a@b.c" }
 * or a multi-kind context
 *   { kind: "multi", user: { key: "u1" }, organization: { key: "acme" } }
 * A context without `kind` is treated as a "user" context.
 */
export type ContextInput = Record<string, unknown>;

export interface SingleContext {
  kind: string;
  key: string;
  anonymous: boolean;
  attributes: Record<string, unknown>;
  privateAttributes: string[];
}

export interface Context {
  kinds: Map<string, SingleContext>;
  /** Stable key for the whole context: the key for single contexts, `kind:key` pairs for multi. */
  canonicalKey: string;
}

const KIND_RE = /^[a-zA-Z0-9._-]+$/;

export class ContextError extends Error {}

function parseSingle(kind: string, raw: unknown): SingleContext {
  if (!KIND_RE.test(kind) || kind === "kind" || kind === "multi") throw new ContextError(`Invalid context kind "${kind}"`);
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new ContextError(`Context "${kind}" must be an object`);
  const obj = raw as Record<string, unknown>;
  if (typeof obj.key !== "string" || obj.key === "") throw new ContextError(`Context "${kind}" needs a non-empty string key`);
  const meta = (obj._meta ?? {}) as { privateAttributes?: unknown };
  const privateAttributes = Array.isArray(meta.privateAttributes) ? meta.privateAttributes.filter((a): a is string => typeof a === "string") : [];
  // No prototype: `constructor`, `toString`, `__proto__` resolve only if the context sets them.
  const attributes: Record<string, unknown> = Object.create(null);
  for (const [k, v] of Object.entries(obj)) if (k !== "_meta" && k !== "kind") attributes[k] = v;
  return { kind, key: obj.key, anonymous: obj.anonymous === true, attributes, privateAttributes };
}

/** Escape ":" and "%" in canonical keys, as LaunchDarkly does. */
const esc = (s: string) => s.replace(/%/g, "%25").replace(/:/g, "%3A");

export function parseContext(input: unknown): Context {
  if (!input || typeof input !== "object" || Array.isArray(input)) throw new ContextError("Context must be an object");
  const obj = input as ContextInput;
  const kinds = new Map<string, SingleContext>();
  if (obj.kind === "multi") {
    for (const [kind, raw] of Object.entries(obj)) if (kind !== "kind") kinds.set(kind, parseSingle(kind, raw));
    if (kinds.size === 0) throw new ContextError("A multi-kind context needs at least one kind");
  } else {
    const kind = typeof obj.kind === "string" ? obj.kind : "user";
    kinds.set(kind, parseSingle(kind, obj));
  }
  const canonicalKey =
    kinds.size === 1 && kinds.has("user")
      ? kinds.get("user")!.key
      : [...kinds.values()]
          .sort((a, b) => a.kind.localeCompare(b.kind))
          .map((c) => `${c.kind}:${esc(c.key)}`)
          .join(":");
  return { kinds, canonicalKey };
}

/**
 * Resolve an attribute reference. Plain names are looked up literally;
 * references starting with "/" are RFC 6901 JSON Pointers into nested objects.
 */
export function getAttribute(ctx: SingleContext, ref: string): unknown {
  if (ref === "kind") return ctx.kind;
  if (ref === "key") return ctx.key;
  if (!ref.startsWith("/")) return Object.hasOwn(ctx.attributes, ref) ? ctx.attributes[ref] : undefined;
  const tokens = ref
    .slice(1)
    .split("/")
    .map((t) => t.replace(/~1/g, "/").replace(/~0/g, "~"));
  let cur: unknown = ctx.attributes;
  for (const [i, t] of tokens.entries()) {
    if (i === 0 && t === "key") return ctx.key;
    if (cur === null || typeof cur !== "object") return undefined;
    if (Array.isArray(cur)) {
      if (!/^(0|[1-9]\d*)$/.test(t)) return undefined;
      cur = cur[Number(t)];
    } else {
      cur = Object.hasOwn(cur, t) ? (cur as Record<string, unknown>)[t] : undefined;
    }
  }
  return cur;
}

export function isFlagValue(v: unknown): v is FlagValue {
  return v === null || ["string", "number", "boolean"].includes(typeof v) || typeof v === "object";
}
