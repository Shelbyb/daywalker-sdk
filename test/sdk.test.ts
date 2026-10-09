import { describe, it } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  canonicalPayload,
  createDaywalker,
  generateSigningKey,
  loadSigningKey,
  publicHostname,
  resolveConfig,
  signRequest,
} from "../src/index.js";

const vectors = JSON.parse(fs.readFileSync(new URL("../test-vectors/signing-v1.json", import.meta.url), "utf8"));

describe("signing protocol (test-vectors/signing-v1.json)", () => {
  const key = loadSigningKey(vectors.privateKeyPkcs8Base64);

  it("derives the published key id and public key", () => {
    assert.deepStrictEqual(key.publicJwk, vectors.publicJwk);
  });

  for (const v of vectors.cases) {
    it(`reproduces "${v.name}" exactly`, () => {
      assert.strictEqual(canonicalPayload(v), v.canonicalPayload);
      const headers = signRequest({ ...v, key, timestamp: Number(v.timestamp) });
      assert.deepStrictEqual(headers, {
        "X-Daywalker-Domain": v.domain,
        "X-Daywalker-Key-Id": vectors.publicJwk.kid,
        "X-Daywalker-Timestamp": v.timestamp,
        "X-Daywalker-Nonce": v.nonce,
        "X-Daywalker-Signature": v.signature,
      });
    });
  }

  it("verifies with the public JWK alone", () => {
    const pub = crypto.createPublicKey({ key: vectors.publicJwk, format: "jwk" });
    for (const v of vectors.cases) {
      assert.ok(crypto.verify(null, Buffer.from(v.canonicalPayload), pub, Buffer.from(v.signature, "base64url")));
    }
  });
});

describe("config", () => {
  it("reads the service slug and reports missing settings", () => {
    assert.deepStrictEqual(resolveConfig({ env: {} }).problems.slice(0, 2), [
      "DAYWALKER_API_KEY is not set",
      "DAYWALKER_SERVICE_SLUG is not set",
    ]);
    assert.strictEqual(resolveConfig({ env: { DAYWALKER_SERVICE_SLUG: " GigPulse " } }).serviceSlug, "gigpulse");
  });

  it("never treats internal addresses as the public domain", () => {
    for (const bad of ["http://0.0.0.0:3000", "localhost:3000", "http://127.0.0.1", "10.0.0.4", "[::1]", "myhost", "x.local"]) {
      assert.strictEqual(publicHostname(bad), null, bad);
    }
    assert.strictEqual(publicHostname("https://Sonalyze.Daywalker.dev/path"), "sonalyze.daywalker.dev");
    const cfg = resolveConfig({ env: { NEXTAUTH_URL: "http://0.0.0.0:3000", NEXT_PUBLIC_APP_URL: "https://gigpulse.daywalker.dev" } });
    assert.deepStrictEqual([cfg.domain, cfg.domainSource], ["gigpulse.daywalker.dev", "NEXT_PUBLIC_APP_URL"]);
    assert.strictEqual(resolveConfig({ env: { DAYWALKER_DOMAIN: "0.0.0.0" } }).domain, null);
  });

  it("publishes current and previous keys, never private material", () => {
    const current = generateSigningKey();
    const previous = generateSigningKey();
    const client = createDaywalker({
      env: { DAYWALKER_SIGNING_KEY: current.privateKey, DAYWALKER_SIGNING_KEY_PREVIOUS: previous.privateKey },
    });
    assert.deepStrictEqual(
      client.keys().keys.map((k) => k.kid),
      [current.publicJwk.kid, previous.publicJwk.kid]
    );
    assert.ok(client.keys().keys.every((k) => !("d" in k)));
  });
});

describe("client", () => {
  const key = generateSigningKey();
  const env = {
    DAYWALKER_API_KEY: "srv_live_example",
    DAYWALKER_SERVICE_SLUG: "sonalyze",
    DAYWALKER_SIGNING_KEY: key.privateKey,
    DAYWALKER_DOMAIN: "sonalyze.daywalker.dev",
  };

  it("sends a signed validate request whose signature verifies", async () => {
    let seen: { url: string; headers: Headers; body: string } | null = null;
    const client = createDaywalker({
      env,
      fetch: async (url, init) => {
        seen = { url: String(url), headers: new Headers(init?.headers), body: String(init?.body) };
        return Response.json({ valid: true, rateLimit: { limit: 60, remaining: 59, reset: 1 }, rateLimitHourly: { limit: 1000, remaining: 999, reset: 2 } });
      },
    });
    const result = await client.validateToken();
    assert.strictEqual(result.valid, true);
    assert.strictEqual(result.signed, true);
    assert.strictEqual(result.data.rateLimitHourly?.limit, 1000);

    const req = seen!;
    assert.strictEqual(req.url, "https://auth.daywalker.dev/api/v1/tokens/validate");
    assert.deepStrictEqual(JSON.parse(req.body), { token: "srv_live_example", serviceSlug: "sonalyze" });
    const payload = canonicalPayload({
      method: "POST",
      path: "/api/v1/tokens/validate",
      domain: req.headers.get("x-daywalker-domain")!,
      timestamp: req.headers.get("x-daywalker-timestamp")!,
      nonce: req.headers.get("x-daywalker-nonce")!,
      body: req.body,
    });
    const pub = crypto.createPublicKey({ key: key.publicJwk, format: "jwk" });
    assert.ok(crypto.verify(null, Buffer.from(payload), pub, Buffer.from(req.headers.get("x-daywalker-signature")!, "base64url")));
  });

  it("caches only successful validations and reports failures", async () => {
    let calls = 0;
    const ok = createDaywalker({ env, fetch: async () => (calls++, Response.json({ valid: true })) });
    await ok.validateToken();
    await ok.validateToken();
    assert.strictEqual(calls, 1);

    const denied = createDaywalker({
      env,
      fetch: async () => Response.json({ valid: false, message: "nope" }, { status: 429, headers: { "Retry-After": "42" } }),
    });
    const res = await denied.validateToken();
    assert.deepStrictEqual([res.valid, res.status, res.retryAfter], [false, 429, 42]);
    await assert.rejects(denied.requireValidToken(), /nope/);

    const down = createDaywalker({ env, fetch: async () => { throw new Error("ECONNREFUSED"); } });
    assert.strictEqual((await down.validateToken()).status, 503);
  });
});

describe("CLI", () => {
  it("init sets up a Next.js project, keeps the key on re-run, and rejects internal domains", () => {
    // The built CLI, exactly as it ships (npm test builds first)
    const cli = path.resolve("dist/cli.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-cli-"));
    const run = (...args: string[]) =>
      execFileSync(process.execPath, [cli, ...args], { cwd: dir, encoding: "utf8", stdio: "pipe" });
    try {
      fs.writeFileSync(path.join(dir, "package.json"), JSON.stringify({ dependencies: { next: "16.0.0" } }));
      fs.mkdirSync(path.join(dir, "app"));
      run("init", "--domain", "https://Demo.Daywalker.dev/", "--service", "demo-svc");

      const route = fs.readFileSync(path.join(dir, "app/.well-known/daywalker-keys.json/route.ts"), "utf8");
      assert.match(route, /export \{ GET, dynamic \} from "@shelbyb\/daywalker-sdk\/next"/);
      const env = fs.readFileSync(path.join(dir, ".env.local"), "utf8");
      assert.match(env, /^# Daywalker Auth/);
      assert.match(env, /DAYWALKER_SERVICE_SLUG="demo-svc"/);
      assert.match(env, /DAYWALKER_DOMAIN="demo.daywalker.dev"/);
      assert.strictEqual(fs.statSync(path.join(dir, ".env.local")).mode & 0o777, 0o600);
      assert.match(fs.readFileSync(path.join(dir, ".gitignore"), "utf8"), /\.env\.local/);

      const keyLine = env.match(/^DAYWALKER_SIGNING_KEY=.*$/m)![0];
      run("init", "--service", "demo-svc");
      assert.ok(fs.readFileSync(path.join(dir, ".env.local"), "utf8").includes(keyLine), "re-running keeps the key");

      assert.throws(() => run("init", "--domain", "0.0.0.0:3000", "--service", "x"));
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
