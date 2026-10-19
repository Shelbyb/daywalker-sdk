import fs from "node:fs";
import path from "node:path";
import { BOOT_NOTICE, GOVERNING_LAW_PLACEHOLDER, HEADER_COMMENT, HEADER_MARKER, LICENSE_TEXT, README_SECTION } from "./templates.js";

export { BOOT_NOTICE, GOVERNING_LAW_PLACEHOLDER, HEADER_COMMENT, LICENSE_TEXT, README_SECTION };

/**
 * `daywalker license apply|check`: puts the DevPulse source-available license into a project (LICENSE file,
 * package.json fields, README section, notice headers on the files that use the SDK, boot log line) and checks
 * that it stays there. Everything it writes is idempotent. It only adds comments and metadata: it never edits
 * code that calls the SDK.
 */

export interface LicenseOptions {
  /** Project root. */
  dir: string;
  /** Report what would change without writing. */
  dryRun?: boolean;
  /** Governing law and venue to put in the LICENSE, e.g. "the State of Delaware, USA" (an owner decision; left as a placeholder otherwise). */
  governingLaw?: string;
  /** Replace a LICENSE file that is not ours. */
  replaceExisting?: boolean;
  /** Extra files (relative to dir) that guard the SDK integration and need the header. */
  include?: string[];
  /** Identifiers whose callers count as guard files (default: the SDK's own validators). */
  guardNames?: string[];
}

export interface LicenseReport {
  changed: string[];
  unchanged: string[];
  /** Things a person must do or confirm. */
  todo: string[];
  /** For check mode: what is missing or out of date. */
  problems: string[];
}

const SDK = "@shelbyb/daywalker-sdk";
const DEFAULT_GUARDS = ["validateServiceCredentials", "validateToken", "getLicense", "fetchBundle"];
const SOURCE_EXT = /\.(?:[cm]?[jt]s|[jt]sx)$/;
const SKIP_DIR = new Set(["node_modules", "dist", "build", ".next", ".git", "coverage", "out", ".turbo", ".cache", "vendor"]);
const SKIP_FILE = /(?:\.test\.|\.spec\.|\.d\.ts$|\.stories\.)/;

const read = (file: string) => fs.readFileSync(file, "utf8");
const rel = (dir: string, file: string) => path.relative(dir, file).split(path.sep).join("/");

function write(dir: string, file: string, content: string, opts: LicenseOptions, report: LicenseReport) {
  const before = fs.existsSync(file) ? read(file) : null;
  if (before === content) {
    report.unchanged.push(rel(dir, file));
    return;
  }
  report.changed.push(rel(dir, file));
  if (!opts.dryRun) fs.writeFileSync(file, content);
}

// ---------- LICENSE ----------

const GOVERNING_RE = /governed by the laws of ([\s\S]+?),\s+excluding its conflict-of-laws rules/;
const PLACEHOLDER_FLAT = GOVERNING_LAW_PLACEHOLDER.replace(/\s+/g, " ");

/** The license text with the governing-law clause filled in (wrapped like the rest of the text). */
function renderLicense(governingLaw?: string): string {
  const body = governingLaw ? LICENSE_TEXT.replace(GOVERNING_LAW_PLACEHOLDER, governingLaw.replace(/\s+/g, " ").trim()) : LICENSE_TEXT;
  return body.endsWith("\n") ? body : `${body}\n`;
}

/** Is this file the license this tool installs (any version)? Compared by title line, so edits are noticed. */
function isOurs(text: string) {
  return text.trimStart().startsWith(LICENSE_TEXT.trimStart().split("\n")[0]!);
}

function applyLicenseFile(opts: LicenseOptions, report: LicenseReport) {
  const file = path.join(opts.dir, "LICENSE");
  const existing = fs.existsSync(file) ? read(file) : null;
  if (existing !== null && !isOurs(existing) && !opts.replaceExisting) {
    report.todo.push("LICENSE exists and is a different license; kept it. Re-run with --replace-existing to replace it (recipients of earlier copies keep the old terms).");
    return;
  }
  // Keep a governing-law clause the owner filled in earlier, unless one is given now.
  const earlier = existing === null ? null : GOVERNING_RE.exec(existing)?.[1];
  const law = opts.governingLaw ?? (earlier && earlier.replace(/\s+/g, " ") !== PLACEHOLDER_FLAT ? earlier : undefined);
  const text = renderLicense(law);
  if (!law) report.todo.push("LICENSE still has the governing-law placeholder: pick the governing law and venue (an owner decision, ideally with counsel) and re-run with --governing-law \"…\".");
  write(opts.dir, file, text, opts, report);
}

// ---------- package.json ----------

function workspaceDirs(dir: string, root: { workspaces?: string[] | { packages?: string[] } }): string[] {
  const patterns = Array.isArray(root.workspaces) ? root.workspaces : (root.workspaces?.packages ?? []);
  const out: string[] = [];
  for (const pattern of patterns) {
    if (pattern.endsWith("/*")) {
      const base = path.join(dir, pattern.slice(0, -2));
      if (fs.existsSync(base)) for (const e of fs.readdirSync(base, { withFileTypes: true })) if (e.isDirectory()) out.push(path.join(base, e.name));
    } else if (!pattern.includes("*")) out.push(path.join(dir, pattern));
  }
  return out.filter((d) => fs.existsSync(path.join(d, "package.json")));
}

function applyPackageJson(file: string, opts: LicenseOptions, report: LicenseReport) {
  const raw = read(file);
  const pkg = JSON.parse(raw) as Record<string, unknown>;
  if (pkg.license === "SEE LICENSE IN LICENSE") {
    report.unchanged.push(rel(opts.dir, file));
  } else {
    // Insert after "private"/"version"/"name" when present so the diff stays small; otherwise append.
    const indent = /^(\s+)"/m.exec(raw)?.[1] ?? "  ";
    const next: Record<string, unknown> = {};
    let placed = false;
    for (const [k, v] of Object.entries(pkg)) {
      if (k === "license") continue;
      next[k] = v;
      if (!placed && k === "private") {
        next.license = "SEE LICENSE IN LICENSE";
        placed = true;
      }
    }
    if (!placed) next.license = "SEE LICENSE IN LICENSE";
    report.changed.push(rel(opts.dir, file));
    if (!opts.dryRun) fs.writeFileSync(file, `${JSON.stringify(next, null, indent)}\n`);
  }
  if (pkg.private === true) report.todo.push(`${rel(opts.dir, file)} is "private": true; left as is (set it to false yourself only if this package is meant to be published).`);
}

// ---------- README ----------

function applyReadme(opts: LicenseOptions, report: LicenseReport) {
  const file = ["README.md", "readme.md", "Readme.md"].map((f) => path.join(opts.dir, f)).find((f) => fs.existsSync(f));
  if (!file) {
    report.todo.push("No README.md found; add the License section by hand.");
    return;
  }
  const text = read(file);
  const section = README_SECTION.trim();
  const lines = text.split("\n");
  const start = lines.findIndex((l) => /^##\s+License\s*$/i.test(l));
  let next: string;
  if (start >= 0) {
    let end = lines.findIndex((l, i) => i > start && /^#{1,2}\s/.test(l));
    if (end < 0) end = lines.length;
    next = [...lines.slice(0, start), ...section.split("\n"), "", ...lines.slice(end)].join("\n").replace(/\n{3,}/g, "\n\n");
    if (!next.endsWith("\n")) next += "\n";
  } else {
    // After the first prose paragraph (skipping the title, badges and blank lines), so it sits near the top.
    let i = 0;
    while (i < lines.length && (lines[i]!.trim() === "" || /^(#|\[!\[|!\[|<)/.test(lines[i]!))) i++;
    while (i < lines.length && lines[i]!.trim() !== "") i++;
    next = [...lines.slice(0, i), "", ...section.split("\n"), ...lines.slice(i)].join("\n");
  }
  write(opts.dir, file, next, opts, report);
}

// ---------- source files ----------

function* walk(dir: string): Generator<string> {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    if (e.isDirectory()) {
      if (!SKIP_DIR.has(e.name) && !e.name.startsWith(".")) yield* walk(path.join(dir, e.name));
    } else if (SOURCE_EXT.test(e.name) && !SKIP_FILE.test(e.name)) yield path.join(dir, e.name);
  }
}

/** Does this file import the SDK or call one of the guard identifiers? */
function usesSdk(source: string, guards: string[]): boolean {
  if (new RegExp(`(?:from\\s*|import\\s*\\(?\\s*|require\\s*\\(\\s*)["']${SDK.replace("/", "\\/")}(?:/[^"']*)?["']`).test(source)) return true;
  return guards.some((g) => new RegExp(`\\b${g}\\s*\\(`).test(source));
}

function addHeader(source: string): string {
  const shebang = /^#![^\n]*\n/.exec(source)?.[0] ?? "";
  return `${shebang}${HEADER_COMMENT}${source.slice(shebang.length)}`;
}

/** Files that need the header: SDK importers and guard callers, plus --include. Documentation content is skipped. */
export function guardFiles(opts: LicenseOptions): string[] {
  const guards = opts.guardNames ?? DEFAULT_GUARDS;
  const found = new Set<string>();
  for (const f of walk(opts.dir)) {
    if (/(?:^|\/)(?:docs?|examples?)\//.test(rel(opts.dir, f))) continue;
    if (usesSdk(read(f), guards)) found.add(f);
  }
  for (const f of opts.include ?? []) {
    const abs = path.resolve(opts.dir, f);
    if (fs.existsSync(abs)) found.add(abs);
  }
  return [...found].sort();
}

function applyHeaders(opts: LicenseOptions, report: LicenseReport) {
  for (const file of guardFiles(opts)) {
    const source = read(file);
    if (source.includes(HEADER_MARKER)) report.unchanged.push(rel(opts.dir, file));
    else write(opts.dir, file, addHeader(source), opts, report);
  }
}

// ---------- boot notice ----------

function bootNoticePresent(dir: string): boolean {
  for (const f of walk(dir)) if (read(f).includes(BOOT_NOTICE)) return true;
  return false;
}

function applyBootNotice(opts: LicenseOptions, report: LicenseReport) {
  if (bootNoticePresent(opts.dir)) return;
  // Next.js loads instrumentation.(ts|js) from the app's root or src/; in a monorepo that is a workspace.
  const instrumentation = [...walk(opts.dir)].filter((f) => /(?:^|\/)instrumentation\.[jt]s$/.test(f.split(path.sep).join("/")));
  const file = instrumentation.sort((a, b) => a.length - b.length)[0];
  if (file) {
    const source = read(file);
    const m = /export\s+(?:async\s+)?function\s+register\s*\([^)]*\)\s*\{\n/.exec(source);
    if (m) {
      const line = `  if (process.env.NEXT_RUNTIME === "nodejs" && process.env.NEXT_PHASE !== "phase-production-build") {\n    console.log("${BOOT_NOTICE}");\n  }\n`;
      write(opts.dir, file, source.slice(0, m.index + m[0].length) + line + source.slice(m.index + m[0].length), opts, report);
      return;
    }
  }
  report.todo.push(`Log this once at server start (server runtime only, not during builds): console.log("${BOOT_NOTICE}")`);
}

// ---------- build output ----------

function adviseBuild(opts: LicenseOptions, report: LicenseReport) {
  const names = fs.readdirSync(opts.dir);
  const bundler = names.find((n) => /^(?:tsup|vite|rollup|webpack|esbuild)\.config\./.test(n));
  const docker = names.includes("Dockerfile");
  if (bundler && !read(path.join(opts.dir, bundler)).includes(HEADER_MARKER)) {
    report.todo.push(`${bundler}: add the notice as a banner comment (tsup/esbuild \`banner.js\`, Vite/Rollup \`output.banner\`, Webpack \`BannerPlugin\` with \`raw: true\`) and copy LICENSE into the output directory.`);
  }
  if (docker && !/COPY\s+[^\n]*\bLICENSE\b/.test(read(path.join(opts.dir, "Dockerfile")))) {
    report.todo.push("Dockerfile: COPY LICENSE into the final image.");
  }
}

// ---------- public API ----------

const empty = (): LicenseReport => ({ changed: [], unchanged: [], todo: [], problems: [] });

export function applyLicense(opts: LicenseOptions): LicenseReport {
  const report = empty();
  applyLicenseFile(opts, report);
  const rootPkg = path.join(opts.dir, "package.json");
  if (fs.existsSync(rootPkg)) {
    applyPackageJson(rootPkg, opts, report);
    const root = JSON.parse(read(rootPkg)) as Parameters<typeof workspaceDirs>[1];
    for (const d of workspaceDirs(opts.dir, root)) applyPackageJson(path.join(d, "package.json"), opts, report);
  } else report.todo.push("No package.json found; set the license field by hand.");
  applyReadme(opts, report);
  applyHeaders(opts, report);
  applyBootNotice(opts, report);
  adviseBuild(opts, report);
  return report;
}

/** Verifies everything `apply` installs; `problems` is empty when the project is compliant. */
export function checkLicense(opts: LicenseOptions): LicenseReport {
  const report = empty();
  const lic = path.join(opts.dir, "LICENSE");
  if (!fs.existsSync(lic)) report.problems.push("LICENSE is missing");
  else {
    const text = read(lic);
    const law = GOVERNING_RE.exec(text)?.[1];
    const flat = law?.replace(/\s+/g, " ").trim();
    if (renderLicense(flat && flat !== PLACEHOLDER_FLAT ? flat : undefined).replace(/\s+/g, " ").trim() !== text.replace(/\s+/g, " ").trim()) {
      report.problems.push("LICENSE differs from the current license text (run `daywalker license apply`)");
    }
    if (!flat || flat === PLACEHOLDER_FLAT) report.todo.push("LICENSE still has the governing-law placeholder (an owner decision).");
  }
  const rootPkg = path.join(opts.dir, "package.json");
  if (fs.existsSync(rootPkg)) {
    const pkgs = [rootPkg, ...workspaceDirs(opts.dir, JSON.parse(read(rootPkg))).map((d) => path.join(d, "package.json"))];
    for (const p of pkgs) if ((JSON.parse(read(p)) as { license?: string }).license !== "SEE LICENSE IN LICENSE") report.problems.push(`${rel(opts.dir, p)}: "license" is not "SEE LICENSE IN LICENSE"`);
  }
  const readme = ["README.md", "readme.md", "Readme.md"].map((f) => path.join(opts.dir, f)).find((f) => fs.existsSync(f));
  if (!readme || !read(readme).includes(README_SECTION.trim())) report.problems.push("README.md is missing the current License section");
  const files = guardFiles(opts);
  if (!files.length) report.todo.push("No file imports the SDK or calls a guard; nothing to put a header on.");
  for (const f of files) if (!read(f).includes(HEADER_MARKER)) report.problems.push(`${rel(opts.dir, f)}: missing the license notice header`);
  if (!bootNoticePresent(opts.dir)) report.problems.push("The boot-time license log line is missing");
  return report;
}

export function formatReport(report: LicenseReport, mode: "apply" | "check", dryRun = false): string {
  const out: string[] = [];
  if (mode === "apply") {
    out.push(`${dryRun ? "Would change" : "Changed"} ${report.changed.length} file(s), ${report.unchanged.length} already up to date.`);
    for (const f of report.changed) out.push(`  ~ ${f}`);
  } else out.push(report.problems.length ? `${report.problems.length} problem(s):` : "License setup is complete.");
  for (const p of report.problems) out.push(`  ✖ ${p}`);
  if (report.todo.length) out.push("", "To do by hand:", ...report.todo.map((t) => `  - ${t}`));
  return out.join("\n");
}
