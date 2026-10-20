import { getAttribute, type Context } from "./context.js";
import { sha1Hex } from "./sha1.js";
import type { Rollout } from "./types.js";

const LONG_SCALE = 0xfffffffffffffff; // 15 hex digits

/**
 * Deterministic bucket in [0, 1) for a context. Compatible with LaunchDarkly:
 * sha1("<flagKey>.<salt>.<value>") (or "<seed>.<value>" for seeded rollouts),
 * first 15 hex digits divided by 0xFFFFFFFFFFFFFFF.
 * Returns null when the context lacks the rollout's context kind.
 */
export function bucketContext(
  ctx: Context,
  key: string,
  salt: string,
  opts: { contextKind?: string; bucketBy?: string; seed?: number },
): { bucket: number; found: boolean } {
  const kind = opts.contextKind ?? "user";
  const single = ctx.kinds.get(kind);
  if (!single) return { bucket: 0, found: false };
  const raw = getAttribute(single, opts.bucketBy ?? "key");
  let id: string;
  if (typeof raw === "string") id = raw;
  else if (typeof raw === "number" && Number.isInteger(raw)) id = String(raw);
  else return { bucket: 0, found: true };
  // `seed: null` (as serialized for "no seed") means unseeded, not the string "null".
  const input = opts.seed !== undefined && opts.seed !== null ? `${opts.seed}.${id}` : `${key}.${salt}.${id}`;
  return { bucket: parseInt(sha1Hex(input).slice(0, 15), 16) / LONG_SCALE, found: true };
}

/** Pick a variation from a rollout. `inExperiment` is true for tracked experiment buckets. */
export function variationForRollout(ctx: Context, flagKey: string, salt: string, rollout: Rollout): { variation: number; inExperiment: boolean } | null {
  if (!rollout.variations.length) return null;
  const { bucket, found } = bucketContext(ctx, flagKey, salt, rollout);
  const isExperiment = rollout.kind === "experiment";
  let sum = 0;
  for (const wv of rollout.variations) {
    sum += wv.weight / 100000;
    if (bucket < sum) return { variation: wv.variation, inExperiment: isExperiment && found && !wv.untracked };
  }
  // Rounding or weights < 100%: fall into the last bucket.
  const last = rollout.variations[rollout.variations.length - 1]!;
  return { variation: last.variation, inExperiment: isExperiment && found && !last.untracked };
}
