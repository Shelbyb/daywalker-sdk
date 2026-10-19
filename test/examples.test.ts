import { readdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { expect } from "./helpers/expect.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as { name: string; exports: Record<string, unknown> };

describe("examples", () => {
  it("every subpath export has an example and the index lists every example", () => {
    const dir = resolve(root, "examples");
    const files = readdirSync(dir).filter((f) => /\.tsx?$/.test(f));
    const code = files.map((f) => readFileSync(resolve(dir, f), "utf8")).join("\n");
    const index = readFileSync(resolve(dir, "README.md"), "utf8");
    for (const sub of Object.keys(pkg.exports)) {
      if (sub === "./package.json") continue;
      const spec = sub === "." ? pkg.name : `${pkg.name}/${sub.slice(2)}`;
      expect(code.includes(`from "${spec}"`)).toBe(true);
    }
    for (const f of files) expect(index.includes(`(./${f})`)).toBe(true);
    // No real-looking secrets in examples.
    expect(/(srv_live_|dps_|dpl_|whsec_)[A-Za-z0-9]{12,}/.test(code)).toBe(false);
  });
});
