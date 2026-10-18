import { describe, it } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import {
  Daywalker,
  assertSecureUrl,
  generateSigningKey,
  resolveConfig,
  signRequest,
  verifyJwtLease,
  verifyRequestSignature,
} from "../src/index.js";
import { SignatureReplayCache } from "../src/crypto/signatures.js";
import { MAX_VALIDATION_CACHE_ENTRIES } from "../src/client.js";
import { STATIC_FILE_EXTENSIONS, createDaywalkerMiddleware, createDaywalkerServiceHealthMiddleware, isStaticAssetPath } from "../src/next.js";
import { createAnalytics, sanitizeUrl } from "../src/analytics/index.js";
import { createClient } from "../src/flags/client.js";
import { init } from "../src/flags/node.js";
import { applyOperator, getAttribute, parseContext } from "../src/flags/engine/index.js";
import { hasNestedQuantifier } from "../src/flags/engine/operators.js";
import { EventProcessor } from "../src/flags/common/index.js";

async function signed(created = Math.floor(Date.now() / 1000), pathName = `/api/v1/replay/${crypto.randomUUID()}`) {
  const key = await generateSigningKey();
  const headers = await signRequest({ method: "POST", path: pathName, authority: "svc.example.com", body: "{}", key, created });
  const verify = (h: Record<string, string | undefined>, extra: Record<string, unknown> = {}) =>
    verifyRequestSignature({ method: "POST", path: pathName, authority: "svc.example.com", headers: h, body: "{}", publicKey: key.publicJwk, currentTime: created, ...extra });
  return { key, headers, verify, created };
}

function reencode(headers: Record<string, string | undefined>, fn: (b64: string) => string) {
  const b64 = headers.Signature!.match(/=:(.*):$/)![1];
  return { ...headers, Signature: `sig1=:${fn(b64)}:` };
}

describe("RFC 9421 replay cache", () => {
  it("only accepts canonical padded base64, so re-encodings can't bypass replay detection", async () => {
    const { headers, verify } = await signed();
    assert.strictEqual((await verify(headers)).valid, true);
    assert.match((await verify(headers)).error!, /Replay detected/);

    const unpadded = await verify(reencode(headers, (b) => b.replace(/=+$/, "")));
    const urlSafe = await verify(reencode(headers, (b) => b.replace(/\+/g, "-").replace(/\//g, "_")));
    assert.strictEqual(unpadded.valid, false);
    assert.strictEqual(urlSafe.valid, false);
    assert.match(unpadded.error!, /byte sequence/);
  });

  it("records replay entries only after the signature verifies", async () => {
    const { headers, key, created } = await signed(undefined, "/api/v1/legit");
    // The same signature presented on a different request fails verification and must not poison the cache.
    const forged = await verifyRequestSignature({ method: "POST", path: "/api/v1/other", authority: "svc.example.com", headers, body: "{}", publicKey: key.publicJwk, currentTime: created });
    assert.match(forged.error!, /verification failed/);
    const legit = await verifyRequestSignature({ method: "POST", path: "/api/v1/legit", authority: "svc.example.com", headers, body: "{}", publicKey: key.publicJwk, currentTime: created });
    assert.strictEqual(legit.valid, true);
  });

  it("keeps entries for at least 2 x maxClockSkewSeconds", async () => {
    const { headers, verify, created } = await signed();
    assert.strictEqual((await verify(headers, { maxClockSkewSeconds: 1000 })).valid, true);
    const realNow = Date.now;
    try {
      Date.now = () => realNow() + 1500 * 1000; // past the old fixed 360s TTL, inside 2 x 1000s
      const replay = await verify(headers, { maxClockSkewSeconds: 1000, currentTime: created + 900 });
      assert.match(replay.error!, /Replay detected/);
    } finally {
      Date.now = realNow;
    }
  });

  it("caps the cache size by refusing new entries, never evicting unexpired ones", () => {
    const cache = new SignatureReplayCache(3);
    const t = 1_000_000;
    assert.deepStrictEqual(["a", "b", "c", "d"].map((k) => cache.record(k, 60_000, t)), [true, true, true, false]);
    assert.strictEqual(cache.size, 3);
    assert.strictEqual(cache.has("a", t), true);
    assert.strictEqual(cache.has("d", t), false);
    assert.strictEqual(cache.record("a", 60_000, t), false); // already present
    // Expired entries make room again.
    assert.strictEqual(cache.record("d", 60_000, t + 60_001), true);
    assert.strictEqual(cache.size, 1);
  });
});

describe("JWT lease claims", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubJwk = crypto.createPublicKey(privateKey).export({ format: "jwk" }) as any;
  const now = Math.floor(Date.now() / 1000);
  const jwt = (payload: Record<string, unknown>, header: Record<string, unknown> = { alg: "EdDSA", typ: "JWT" }) => {
    const h = Buffer.from(JSON.stringify(header)).toString("base64url");
    const b = Buffer.from(JSON.stringify({ jti: "j1", iss: "https://auth.daywalker.dev", ...payload })).toString("base64url");
    return `${h}.${b}.${crypto.sign(null, Buffer.from(`${h}.${b}`), privateKey).toString("base64url")}`;
  };
  const verify = (token: string, extra: Record<string, unknown> = {}) =>
    verifyJwtLease({ token, publicKey: pubJwk, expectedServiceSlug: "myservice", currentTime: now, ...extra });

  it("requires exp, an expected audience, a matching aud/serviceSlug, iss and typ", async () => {
    assert.strictEqual((await verify(jwt({ aud: "myservice", exp: now + 60 }))).valid, true);
    assert.match((await verify(jwt({ aud: "myservice" }))).error!, /no numeric exp/);
    assert.match((await verify(jwt({ aud: "myservice", exp: now + 60 }), { expectedServiceSlug: undefined })).error!, /no expected service slug/);
    assert.match((await verify(jwt({ exp: now + 60 }))).error!, /no aud or serviceSlug/);
    assert.match((await verify(jwt({ aud: "other", serviceSlug: "myservice", exp: now + 60 }))).error!, /mismatch/);
    assert.match((await verify(jwt({ aud: "myservice", exp: now + 60, iss: "https://evil" }), { expectedIssuer: "https://auth.daywalker.dev" })).error!, /issuer mismatch/);
    assert.match((await verify(jwt({ aud: "myservice", exp: now + 60 }, { alg: "EdDSA", typ: "rt+jwt" }))).error!, /typ/);
  });

  it("allows a small bounded clock skew on exp", async () => {
    assert.strictEqual((await verify(jwt({ aud: "myservice", exp: now - 29 }))).valid, true);
    assert.match((await verify(jwt({ aud: "myservice", exp: now - 31 }))).error!, /expired/);
  });

  it("never caches a lease past its exp", async () => {
    const client = new Daywalker({ serviceSlug: "myservice", daywalkerPublicKey: pubJwk, cacheTtlMs: 600_000, fetch: async () => Response.json({}) });
    const exp = Math.floor(Date.now() / 1000) + 5;
    const result = await client.validateToken(jwt({ aud: "myservice", exp }));
    assert.strictEqual(result.ok, true);
    const [entry] = [...(client as any)._cache.values()];
    assert.ok(entry.expiresAt <= exp * 1000);
  });
});

describe("Per-request auth never falls back to the service key", () => {
  it("rejects requests without a token with 401 and never calls Daywalker", async () => {
    let calls = 0;
    const client = new Daywalker({ apiKey: "srv_live_service_key", serviceSlug: "svc", fetch: async () => (calls++, Response.json({ valid: true, tenantId: "t" })) });
    const mw = createDaywalkerMiddleware({ client });
    const res = await mw(new Request("https://app.example.com/api/data"));
    assert.strictEqual(res.status, 401);
    assert.strictEqual((await client.validateToken({ serviceSlug: "svc" })).status, 401);
    assert.strictEqual(calls, 0);

    // The service-health gate is separate and explicitly named.
    const health = createDaywalkerServiceHealthMiddleware({ client });
    assert.strictEqual((await health(new Request("https://app.example.com/dashboard"))).headers.get("x-middleware-next"), "1");
    assert.strictEqual(calls, 1);
  });
});

describe("Next middleware static bypass", () => {
  it("skips only Next static output and the favicon (extensions are opt-in), never /api", async () => {
    for (const p of ["/_next/static/chunks/app.js", "/_next/image", "/favicon.ico"]) {
      assert.strictEqual(isStaticAssetPath(p), true, p);
    }
    for (const p of ["/logo.png", "/fonts/a.woff2", "/robots.txt"]) {
      assert.strictEqual(isStaticAssetPath(p), false, p);
      assert.strictEqual(isStaticAssetPath(p, STATIC_FILE_EXTENSIONS), true, p);
    }
    for (const p of ["/_next/data/build/page.json", "/api/report.js", "/api/x.png", "/dashboard", "/export.pdf", "/_next/webpack-hmr"]) {
      assert.strictEqual(isStaticAssetPath(p, STATIC_FILE_EXTENSIONS), false, p);
    }
    const client = new Daywalker({ serviceSlug: "svc", fetch: async () => Response.json({ valid: true }) });
    const mw = createDaywalkerMiddleware({ client, protectApiOnly: true });
    assert.strictEqual((await mw(new Request("https://app.example.com/api/report.js"))).status, 401);
  });
});

describe("Validation cache", () => {
  it("is bounded and keyed by a token hash, not the raw token", async () => {
    const client = new Daywalker({ serviceSlug: "svc", fetch: async () => Response.json({ valid: true, tenantId: "t" }) });
    for (let i = 0; i < MAX_VALIDATION_CACHE_ENTRIES + 50; i++) await client.validateToken(`tok_raw_secret_${i}`);
    const keys = [...(client as any)._cache.keys()] as string[];
    assert.strictEqual(keys.length, MAX_VALIDATION_CACHE_ENTRIES);
    assert.strictEqual(keys.some((k) => k.includes("tok_raw_secret")), false);
  });
});

describe("Analytics URL privacy", () => {
  it("drops fragments and non-campaign query parameters", () => {
    assert.strictEqual(
      sanitizeUrl("https://app.example.com/cb?code=oauth123&state=x&utm_source=news&gclid=g1#access_token=abc"),
      "https://app.example.com/cb?utm_source=news&gclid=g1"
    );
    assert.strictEqual(sanitizeUrl("https://app.example.com/reset?token=secret"), "https://app.example.com/reset");
  });
});

describe("Transport security", () => {
  it("requires https for authUrl, flags baseUrl and analytics host (except localhost)", () => {
    assert.throws(() => resolveConfig({ authUrl: "http://auth.example.com" }), /https/);
    assert.strictEqual(resolveConfig({ authUrl: "http://localhost:8787" }).authUrl, "http://localhost:8787");
    assert.doesNotThrow(() => assertSecureUrl("x", "http://127.0.0.1:3000"));
    assert.doesNotThrow(() => assertSecureUrl("x", "http://[::1]:3000"));
    assert.throws(() => createClient("cid", { key: "u" }, { baseUrl: "http://flags.example.com", sendEvents: false }), /https/);
    assert.throws(() => init("sdk", { baseUrl: "http://flags.example.com", stream: false, sendEvents: false }), /https/);
    assert.throws(() => createAnalytics({ writeKey: "dpa_x", host: "http://dp.example.com" }), /https/);
  });

  it("refuses to send the API key to another origin from fetch()", async () => {
    let calls = 0;
    const client = new Daywalker({ apiKey: "srv_live_secret", fetch: async () => (calls++, Response.json({})) });
    await assert.rejects(client.fetch("https://evil.example.com/steal"), /Refusing/);
    await assert.rejects(client.fetch("//evil.example.com/steal"), /Refusing/);
    assert.strictEqual(calls, 0);
  });
});

describe("CLI secret handling", () => {
  it("chmods an existing env file to 0600 and warns about --api-key", { skip: process.platform === "win32" }, () => {
    const cli = path.resolve("dist/cli.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-cli-"));
    try {
      const envFile = path.join(dir, ".env.local");
      fs.writeFileSync(envFile, "OTHER=1\n", { mode: 0o644 });
      fs.chmodSync(envFile, 0o644);
      const run = spawnSync(process.execPath, [cli, "init", "--service", "svc", "--api-key", "srv_live_cli", "--skip-register"], { cwd: dir, encoding: "utf8" });
      assert.strictEqual(run.status, 0, run.stderr);
      assert.match(run.stderr, /--api-key exposes the key/);
      assert.strictEqual(fs.statSync(envFile).mode & 0o777, 0o600);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("matches operator limits", () => {
  it("caps input and pattern length and rejects nested quantifiers", () => {
    assert.strictEqual(applyOperator("matches", "a".repeat(1024), "^a+$"), true);
    assert.strictEqual(applyOperator("matches", "a".repeat(1025), "^a+$"), false);
    assert.strictEqual(applyOperator("matches", "a", "a|" + "b".repeat(500)), false);
    for (const p of ["(a+)+$", "(a*)*", "(a|aa)+", "(?:x+y)*", "((ab)+)+", "(a+){2,}"]) assert.strictEqual(hasNestedQuantifier(p), true, p);
    for (const p of ["^a.*\\.dev$", "(abc)+", "(a+)?b", "[(+)]+", "\\(a+\\)+"]) assert.strictEqual(hasNestedQuantifier(p), false, p);
    assert.strictEqual(applyOperator("matches", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!", "^(a+)+$"), false);
  });
});

describe("Prototype-safe attribute and flag lookups", () => {
  it("never resolves inherited properties", () => {
    const single = parseContext({ key: "u1", address: { zip: "1" } }).kinds.get("user")!;
    for (const ref of ["constructor", "toString", "__proto__", "/constructor", "/address/constructor", "/address/toString"]) {
      assert.strictEqual(getAttribute(single, ref), undefined, ref);
    }
    assert.strictEqual(getAttribute(single, "/address/zip"), "1");

    const client = createClient("cid", { key: "u1" }, { baseUrl: "https://x", streaming: false, sendEvents: false, bootstrap: { a: true }, fetch: (async () => Response.json({ a: { value: true, variation: 0, version: 1 } })) as unknown as typeof fetch });
    assert.strictEqual(client.variation("toString", "dflt"), "dflt");
    assert.strictEqual(client.variation("constructor", "dflt"), "dflt");
    assert.strictEqual(client.variationDetail("__proto__", "dflt").reason?.kind, "ERROR");
    void client.close();
  });
});

describe("Event redaction", () => {
  it("redacts nested values named by JSON pointers", async () => {
    const ep = new EventProcessor({ url: "https://x/events", privateAttributes: ["/address/zip"], fetch: (async () => new Response(null)) as unknown as typeof fetch });
    const input = { key: "u1", address: { zip: "94110", city: "SF" } };
    const out = ep.redact(input);
    assert.deepStrictEqual(out.address, { city: "SF" });
    assert.deepStrictEqual(out.redactedAttributes, ["/address/zip"]);
    assert.strictEqual(input.address.zip, "94110"); // the caller's context isn't mutated
    await ep.close();
  });
});
