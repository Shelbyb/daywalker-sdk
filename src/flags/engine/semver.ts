/**
 * Semantic Versioning 2.0.0 comparison. Like LaunchDarkly, versions missing a
 * minor or patch component ("2" or "2.1") are accepted and padded with zeros.
 */
export interface SemVer {
  major: number;
  minor: number;
  patch: number;
  prerelease: string[];
}

const RE = /^v?(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?(?:\.(0|[1-9]\d*))?(?:-((?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*)(?:\.(?:0|[1-9]\d*|\d*[a-zA-Z-][0-9a-zA-Z-]*))*))?(?:\+([0-9a-zA-Z-]+(?:\.[0-9a-zA-Z-]+)*))?$/;

export function parseSemVer(input: unknown): SemVer | null {
  if (typeof input !== "string") return null;
  const m = RE.exec(input.trim());
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2] ?? 0), patch: Number(m[3] ?? 0), prerelease: m[4] ? m[4].split(".") : [] };
}

/** Precedence per SemVer §11. Build metadata is ignored. */
export function compareSemVer(a: SemVer, b: SemVer): number {
  for (const k of ["major", "minor", "patch"] as const) if (a[k] !== b[k]) return a[k] < b[k] ? -1 : 1;
  if (!a.prerelease.length || !b.prerelease.length) return a.prerelease.length === b.prerelease.length ? 0 : a.prerelease.length ? -1 : 1;
  for (let i = 0; i < Math.max(a.prerelease.length, b.prerelease.length); i++) {
    const x = a.prerelease[i];
    const y = b.prerelease[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    if (x === y) continue;
    const xn = /^\d+$/.test(x);
    const yn = /^\d+$/.test(y);
    if (xn && yn) return Number(x) < Number(y) ? -1 : 1;
    if (xn !== yn) return xn ? -1 : 1;
    return x < y ? -1 : 1;
  }
  return 0;
}
