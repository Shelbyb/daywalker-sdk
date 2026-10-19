import { describe, it } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { applyLicense, checkLicense, formatReport, guardFiles, BOOT_NOTICE, HEADER_COMMENT, LICENSE_TEXT } from "../src/license/index.js";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const TSX = import.meta.resolve("tsx");

function project(files: Record<string, string>) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-license-"));
  for (const [f, content] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, f)), { recursive: true });
    fs.writeFileSync(path.join(dir, f), content);
  }
  return dir;
}
const read = (dir: string, f: string) => fs.readFileSync(path.join(dir, f), "utf8");

const files = () => ({
  "package.json": JSON.stringify({ name: "root", private: true, workspaces: ["apps/*"], version: "1.0.0" }, null, 2) + "\n",
  "apps/web/package.json": JSON.stringify({ name: "web", private: true }, null, 2) + "\n",
  "README.md": "# Demo\n\n[![CI](x)](y)\n\nA demo app.\nSecond line.\n\n## Usage\n\nRun it.\n",
  "apps/web/src/guard.ts": 'import { createDaywalker } from "@shelbyb/daywalker-sdk";\nexport const dw = createDaywalker({} as never);\n',
  "apps/web/src/cli.mjs": '#!/usr/bin/env node\nimport("@shelbyb/daywalker-sdk/next");\n',
  "apps/web/src/proxy.ts": '"use client";\nimport { requireAuth } from "./guard";\nvalidateServiceCredentials({});\n',
  "apps/web/src/other.ts": "export const x = 1;\n",
  "apps/web/src/guard.test.ts": 'import "@shelbyb/daywalker-sdk";\n',
  "apps/web/src/instrumentation.ts": "export async function register() {\n  start();\n}\n",
  "docs/example.ts": 'import "@shelbyb/daywalker-sdk";\n',
  "node_modules/dep/index.js": 'require("@shelbyb/daywalker-sdk");\n',
});

describe("license apply", () => {
  it("installs everything, changes nothing it should not, and is idempotent", () => {
    const dir = project(files());
    const r = applyLicense({ dir, governingLaw: "the State of Delaware, USA" });
    assert.ok(read(dir, "LICENSE").includes("the State of Delaware, USA, excluding its conflict-of-laws rules"));
    assert.equal(JSON.parse(read(dir, "package.json")).license, "SEE LICENSE IN LICENSE");
    assert.equal(JSON.parse(read(dir, "package.json")).private, true, "private is never changed");
    assert.equal(JSON.parse(read(dir, "apps/web/package.json")).license, "SEE LICENSE IN LICENSE");
    assert.ok(r.todo.some((t) => t.includes("package.json is \"private\": true")));
    // README: after the first prose paragraph, before ## Usage
    const readme = read(dir, "README.md");
    assert.ok(readme.indexOf("## License") > readme.indexOf("A demo app.") && readme.indexOf("## License") < readme.indexOf("## Usage"));
    // Headers: SDK importers (incl. dynamic import and the shebang case) and guard callers; not tests, docs, deps or unrelated files
    assert.ok(read(dir, "apps/web/src/guard.ts").startsWith(HEADER_COMMENT));
    assert.ok(read(dir, "apps/web/src/cli.mjs").startsWith("#!/usr/bin/env node\n/*"));
    assert.ok(read(dir, "apps/web/src/proxy.ts").startsWith(HEADER_COMMENT + '"use client";'));
    assert.ok(!read(dir, "apps/web/src/other.ts").includes("Copyright"));
    assert.ok(!read(dir, "apps/web/src/guard.test.ts").includes("Copyright"));
    assert.ok(!read(dir, "docs/example.ts").includes("Copyright"));
    assert.ok(!read(dir, "node_modules/dep/index.js").includes("Copyright"));
    // Boot notice goes into Next's register()
    assert.ok(read(dir, "apps/web/src/instrumentation.ts").includes(BOOT_NOTICE));
    // Second run: nothing changes
    const again = applyLicense({ dir, governingLaw: "the State of Delaware, USA" });
    assert.deepEqual(again.changed, []);
    assert.equal(checkLicense({ dir }).problems.length, 0);
  });

  it("dry run writes nothing", () => {
    const dir = project(files());
    const r = applyLicense({ dir, dryRun: true });
    assert.ok(r.changed.length > 5);
    assert.ok(!fs.existsSync(path.join(dir, "LICENSE")));
    assert.ok(!read(dir, "apps/web/src/guard.ts").includes("Copyright"));
    assert.ok(/Would change/.test(formatReport(r, "apply", true)));
  });

  it("keeps a different LICENSE unless told to replace it, and keeps a filled-in governing law", () => {
    const dir = project({ ...files(), LICENSE: "MIT License\n\nCopyright someone\n" });
    const r = applyLicense({ dir });
    assert.ok(read(dir, "LICENSE").startsWith("MIT License"));
    assert.ok(r.todo.some((t) => t.includes("--replace-existing")));
    applyLicense({ dir, replaceExisting: true, governingLaw: "England and Wales" });
    assert.ok(read(dir, "LICENSE").startsWith(LICENSE_TEXT.split("\n")[0]));
    applyLicense({ dir }); // no flag: the earlier choice stays
    assert.ok(read(dir, "LICENSE").includes("England and Wales, excluding"));
  });

  it("replaces an existing License section and handles a README without a paragraph", () => {
    const dir = project({ ...files(), "README.md": "# T\n\n## License\nOld text.\n\n## Other\nx\n" });
    applyLicense({ dir });
    const readme = read(dir, "README.md");
    assert.ok(!readme.includes("Old text."));
    assert.equal(readme.match(/## License/g)?.length, 1);
    assert.ok(readme.includes("## Other"));
  });

  it("reports build and logging steps it cannot do safely", () => {
    const dir = project({ ...files(), "apps/web/src/instrumentation.ts": "export const x = 1;\n", Dockerfile: "FROM node\nCOPY . .\n", "tsup.config.ts": "export default {};\n" });
    const r = applyLicense({ dir });
    assert.ok(r.todo.some((t) => t.includes("console.log")));
    assert.ok(r.todo.some((t) => t.startsWith("Dockerfile")));
    assert.ok(r.todo.some((t) => t.startsWith("tsup.config.ts")));
  });

  it("honours --include and custom guard names", () => {
    const dir = project({ "package.json": "{}\n", "src/a.ts": "assertLicensed();\n", "src/b.ts": "export const b = 1;\n" });
    const found = guardFiles({ dir, include: ["src/b.ts"], guardNames: ["assertLicensed"] }).map((f) => path.basename(f));
    assert.deepEqual(found, ["a.ts", "b.ts"]);
  });
});

describe("license check", () => {
  it("lists what is missing", () => {
    const dir = project(files());
    const r = checkLicense({ dir });
    const text = r.problems.join("\n");
    for (const needle of ["LICENSE is missing", "package.json", "README.md", "guard.ts: missing", "boot-time"]) assert.ok(text.includes(needle), needle);
    assert.ok(/problem/.test(formatReport(r, "check")));
  });

  it("notices an edited LICENSE and a stripped header", () => {
    const dir = project(files());
    applyLicense({ dir, governingLaw: "Utah" });
    fs.writeFileSync(path.join(dir, "LICENSE"), read(dir, "LICENSE").replace("ACCEPTANCE", "NOTHING"));
    fs.writeFileSync(path.join(dir, "apps/web/src/guard.ts"), 'import { createDaywalker } from "@shelbyb/daywalker-sdk";\n');
    const text = checkLicense({ dir }).problems.join("\n");
    assert.ok(text.includes("LICENSE differs"));
    assert.ok(text.includes("guard.ts: missing"));
  });

  it("flags the governing-law placeholder as a to-do, not a failure", () => {
    const dir = project(files());
    applyLicense({ dir });
    const r = checkLicense({ dir });
    assert.deepEqual(r.problems, []);
    assert.ok(r.todo.some((t) => t.includes("governing-law")));
    assert.ok(formatReport(r, "check").includes("complete"));
  });
});

describe("daywalker license (CLI)", () => {
  const run = (args: string[]) => spawnSync(process.execPath, ["--import", TSX, CLI, ...args], { encoding: "utf8" });

  it("apply then check exits 0; check on a bare project exits 1; bad usage exits 1", () => {
    const dir = project(files());
    assert.equal(run(["license", "check", "--dir", dir]).status, 1);
    const apply = run(["license", "apply", "--dir", dir, "--governing-law", "Texas"]);
    assert.equal(apply.status, 0, apply.stderr);
    assert.ok(apply.stdout.includes("Changed"));
    assert.equal(run(["license", "check", "--dir", dir]).status, 0);
    assert.equal(run(["license", "nope"]).status, 1);
    assert.equal(run(["license", "check", "--dir", path.join(dir, "missing")]).status, 1);
  });
});
