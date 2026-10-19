import { createHmac, createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { describe, it } from "node:test";
import { fileURLToPath } from "node:url";
import { expect } from "./helpers/expect.js";
import { Emitter } from "../src/flags/common/emitter.js";
import { hmacSha256Hex, sha256 } from "../src/flags/common/hmac.js";
import { init } from "../src/flags/node.js";
import { createAnalytics } from "../src/analytics/index.js";
import { createApiClient } from "../src/api/index.js";
import { createClient } from "../src/flags/client.js";
import { signWebhook, verifyWebhook } from "../src/webhooks/index.js";
import { createCronMonitor } from "../src/cron/index.js";
import { createLogger } from "../src/logs/index.js";
import { fetchSecrets } from "../src/secrets/index.js";
import { createOncall } from "../src/oncall/index.js";
import { createSloReporter } from "../src/slo/index.js";
import { recordDeploy } from "../src/deploys/index.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const pkg = JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as { exports: Record<string, string | { types?: string; import?: string; default?: string }>; sideEffects: boolean };

/** Portable entry points: they must not pull in Node built-ins, directly or transitively. */
const PORTABLE = ["./flags", "./flags/node", "./flags/react", "./flags/engine", "./openfeature/web", "./analytics", "./api", "./webhooks", "./cron", "./logs", "./secrets", "./secrets/env", "./oncall", "./slo", "./deploys"];

function srcOf(distPath: string) {
  const p = resolve(root, distPath.replace(/^\.\/dist\//, "src/").replace(/\.js$/, ""));
  return [".ts", ".tsx"].map((e) => p + e).find(existsSync)!;
}

function graph(entry: string, seen = new Set<string>()): Set<string> {
  if (seen.has(entry)) return seen;
  seen.add(entry);
  const code = readFileSync(entry, "utf8");
  for (const m of code.matchAll(/(?:import|export)\s[^"']*?from\s+["']([^"']+)["']|import\(["']([^"']+)["']\)/g)) {
    const spec = (m[1] ?? m[2])!;
    if (spec.startsWith(".")) {
      const base = resolve(dirname(entry), spec).replace(/\.js$/, "");
      graph([".ts", ".tsx", "/index.ts"].map((e) => base + e).find(existsSync)!, seen);
    }
    else seen.add(`pkg:${spec}`);
  }
  return seen;
}

describe("runtime compatibility", () => {
  it("portable entry points import no Node built-ins and only allowed packages", () => {
    for (const sub of PORTABLE) {
      const entry = pkg.exports[sub] as { import: string };
      const files = graph(srcOf(entry.import));
      for (const f of files) {
        if (f.startsWith("pkg:")) {
          const name = f.slice(4);
          expect(/^(node:|fs$|path$|crypto$|events$|os$|url$|http$|https$|stream$|buffer$)/.test(name)).toBe(false);
          expect(["re2js", "react", "@openfeature/core", "@openfeature/web-sdk", "@openfeature/server-sdk"].some((a) => name === a || name.startsWith(a + "/"))).toBe(true);
        } else {
          const text = readFileSync(f, "utf8");
          expect(/\bBuffer\b(?!s)|\brequire\(|__dirname|process\.(?!env)/.test(text.replace(/\/\*[\s\S]*?\*\/|\/\/.*$/gm, ""))).toBe(false);
        }
      }
    }
  });

  it("only re2js is a runtime dependency and the package is side-effect free", () => {
    expect(pkg.sideEffects).toBe(false);
    expect(Object.keys((JSON.parse(readFileSync(resolve(root, "package.json"), "utf8")) as { dependencies: object }).dependencies)).toEqual(["re2js"]);
  });

  it("every subpath export has types, import and default", () => {
    for (const [k, v] of Object.entries(pkg.exports)) {
      if (typeof v === "string") continue;
      expect(typeof v.types).toBe("string");
      expect(typeof v.import).toBe("string");
      expect(typeof v.default).toBe("string");
      expect(k.startsWith(".")).toBe(true);
    }
    for (const sub of ["./flags", "./flags/node", "./analytics", "./api", "./webhooks", "./cron", "./logs", "./secrets", "./secrets/env", "./oncall", "./slo", "./deploys"]) expect(sub in pkg.exports).toBe(true);
  });

  it("runs with browser/worker globals only (no process, no Buffer)", async () => {
    const g = globalThis as Record<string, unknown>;
    const saved = { process: g.process, Buffer: g.Buffer };
    // Node loads its fetch internals (undici) lazily, and they need Buffer: load them first.
    await new Response("warm").text();
    try {
      delete g.Buffer;
      Object.defineProperty(globalThis, "process", { value: undefined, configurable: true, writable: true });
      expect(typeof createAnalytics({ writeKey: "dpa_x", host: "https://dp.example.com" }).getDistinctId()).toBe("string");
      expect(createApiClient({ host: "https://dp.example.com", clientId: "a", clientSecret: "b" }).host).toBe("https://dp.example.com");
      expect(typeof createClient).toBe("function");
      const server = init("sdk-key", { baseUrl: "https://dp.example.com", offline: true });
      expect(server.secureModeHash({ key: "u1" })).toBe(createHmac("sha256", "sdk-key").update("u1").digest("hex"));
      server.close?.();
      // A Response-shaped stub: Node's own Response constructor needs Buffer.
      const text = JSON.stringify({ secrets: { A: "1" } });
      const ok = (async () => ({ ok: true, status: 200, headers: new Headers(), body: null, text: async () => text, json: async () => JSON.parse(text) })) as unknown as typeof fetch;
      const secret = "whsec_" + btoa("k".repeat(32));
      const body = JSON.stringify({ type: "ping", timestamp: "", data: {} });
      const headers = { "webhook-id": "m", "webhook-timestamp": "100", "webhook-signature": await signWebhook(secret, "m", 100, body) };
      expect((await verifyWebhook({ secret, headers, body, now: 100_000 })).type).toBe("ping");
      expect((await createCronMonitor({ pingUrl: "https://dp.example.com/ping/t", fetch: ok }).success()).ok).toBe(true);
      const log = createLogger({ host: "https://dp.example.com", token: "dpl_x", fetch: ok, flushIntervalMs: 0 });
      log.info("hi");
      await log.shutdown();
      expect((await fetchSecrets({ host: "https://dp.example.com", token: "dps_x", fetch: ok })).secrets.A).toBe("1");
      expect(typeof createOncall({ host: "https://dp.example.com", routingKey: "rk_x" }).trigger).toBe("function");
      const api = { post: async () => ({ data: { id: "d1" } }) } as never;
      await createSloReporter({ api, project: "p", slo: "s", flushIntervalMs: 0 }).shutdown();
      expect((await recordDeploy(api, "p", { environment: "production" })).id).toBe("d1");
    } finally {
      Object.defineProperty(globalThis, "process", { value: saved.process, configurable: true, writable: true });
      g.Buffer = saved.Buffer;
    }
  });
});

describe("portable primitives", () => {
  it("sha256 and HMAC-SHA256 match node:crypto, including long keys and multi-block input", () => {
    const enc = new TextEncoder();
    for (const msg of ["", "abc", "a".repeat(55), "a".repeat(56), "a".repeat(64), "héllo wörld ✓".repeat(40)]) {
      expect(Buffer.from(sha256(enc.encode(msg))).toString("hex")).toBe(createHash("sha256").update(msg).digest("hex"));
      for (const key of ["k", "", "x".repeat(64), "y".repeat(200)]) expect(hmacSha256Hex(key, msg)).toBe(createHmac("sha256", key).update(msg).digest("hex"));
    }
  });

  it("Emitter mirrors the EventEmitter subset the clients use", () => {
    const e = new Emitter();
    const seen: unknown[] = [];
    const fn = (x: unknown) => seen.push(x);
    expect(e.emit("a")).toBe(false);
    e.on("a", fn).addListener("a", fn);
    e.once("a", (x) => seen.push(`once:${x}`));
    expect(e.listenerCount("a")).toBe(3);
    expect(e.emit("a", 1)).toBe(true);
    expect(seen).toEqual([1, 1, "once:1"]);
    e.emit("a", 2);
    expect(seen.length).toBe(5);
    e.off("a", fn);
    e.removeListener("a", fn);
    e.removeListener("zzz", fn);
    expect(e.listenerCount("a")).toBe(0);
    const once = () => {};
    e.once("b", once);
    e.off("b", once);
    expect(e.listenerCount("b")).toBe(0);
    e.on("c", fn).on("d", fn);
    e.removeAllListeners("c");
    expect(e.listenerCount("c")).toBe(0);
    e.removeAllListeners();
    expect(e.listenerCount("d")).toBe(0);
    e.on("x", () => {
      e.off("x", fn);
    });
    e.emit("x");
  });
});
