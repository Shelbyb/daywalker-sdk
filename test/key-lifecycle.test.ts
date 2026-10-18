import { describe, it } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import type { AddressInfo } from "node:net";
import { Daywalker, generateSigningKey, keySlotFor, listSigningKeys, registerPublicKey, revokeSigningKey, verifyRequestSignature, type PublicJwk } from "../src/index.js";
import { memoryKeyStore } from "../src/keystore/index.js";
import { withOAuth, type TokenRequestLog } from "./helpers/oauth.js";

const env = {};
const DOMAIN = "app.example.com";
const API_KEY = "srv_live_service_key";

type Key = { keyId: string; domain: string; jwk: PublicJwk; status: "ACTIVE" | "ROTATING" | "REVOKED"; instanceId: string | null; expiresAt: number | null; createdAt: number };

/**
 * A fake of Daywalker's key lifecycle (per the implementation behind /docs): one key per (domain, instanceId)
 * slot, the previous ACTIVE key of a slot moves to ROTATING (10 minutes), idempotent re-registration (200),
 * a cap of 20 live keys per domain, ttlSeconds / expiresAt, list and revoke.
 */
function fakeDaywalker(options: { expiresIn?: (ttl: number | undefined) => number | null; failRegister?: () => Response | null; validate?: () => Response } = {}) {
  const keys = new Map<string, Key>();
  const calls: { method: string; path: string; body: any; authorization: string | null }[] = [];
  const validated: { headers: Headers; body: string }[] = [];
  const now = () => Math.floor(Date.now() / 1000);
  const live = (k: Key) => k.status !== "REVOKED" && (k.expiresAt === null || k.expiresAt > now());
  const record = (k: Key) => ({ id: `sk_${k.keyId.slice(0, 6)}`, keyId: k.keyId, domain: k.domain, status: live(k) ? k.status : "REVOKED", instanceId: k.instanceId, expiresAt: k.expiresAt ? new Date(k.expiresAt * 1000).toISOString() : null, createdAt: new Date(k.createdAt * 1000).toISOString(), lastUsedAt: null });

  const fetch = withOAuth(async (url, init) => {
    const u = new URL(String(url));
    const method = init?.method ?? "GET";
    const authorization = new Headers(init?.headers).get("authorization");
    const body = init?.body ? JSON.parse(String(init.body)) : null;
    if (u.pathname.startsWith("/api/v1/keys")) calls.push({ method, path: u.pathname + u.search, body, authorization });
    if (u.pathname === "/api/v1/keys/register") {
      const failure = options.failRegister?.();
      if (failure) return failure;
      const existing = keys.get(body.keyId);
      if (existing) {
        return existing.jwk.x === body.publicKey.x && existing.domain === body.domain ? Response.json(record(existing), { status: 200 }) : Response.json({ error: "KEY_ID_CONFLICT", message: "conflict" }, { status: 409 });
      }
      if ([...keys.values()].filter((k) => k.domain === body.domain && live(k)).length >= 20) {
        return Response.json({ error: "KEY_LIMIT_REACHED", message: "Maximum limit of 20 active or rotating keys reached" }, { status: 409 });
      }
      for (const k of keys.values()) {
        if (k.domain === body.domain && k.status === "ACTIVE" && k.instanceId === (body.instanceId ?? null)) {
          k.status = "ROTATING";
          k.expiresAt = Math.min(k.expiresAt ?? Infinity, now() + 600);
        }
      }
      const expiresAt = options.expiresIn ? options.expiresIn(body.ttlSeconds) : body.ttlSeconds ? now() + body.ttlSeconds : null;
      const key: Key = { keyId: body.keyId, domain: body.domain, jwk: body.publicKey, status: "ACTIVE", instanceId: body.instanceId ?? null, expiresAt, createdAt: now() };
      keys.set(key.keyId, key);
      return Response.json(record(key), { status: 201 });
    }
    if (u.pathname === "/api/v1/keys" && method === "GET") {
      const domain = u.searchParams.get("domain");
      return Response.json({ keys: [...keys.values()].filter((k) => k.domain === domain).map(record) });
    }
    if (u.pathname.startsWith("/api/v1/keys/") && method === "DELETE") {
      const key = keys.get(decodeURIComponent(u.pathname.split("/").pop()!));
      if (!key) return Response.json({ error: "key_not_found", message: "Signing key not found" }, { status: 404 });
      key.status = "REVOKED";
      return Response.json({ success: true });
    }
    validated.push({ headers: new Headers(init?.headers), body: String(init?.body) });
    return options.validate?.() ?? Response.json({ valid: true, serviceSlug: "svc", tenantId: "t" });
  }, { log: (globalThis as any).__tokenLog });
  return { fetch, keys, calls, validated, live };
}

const verifyWith = (req: { headers: Headers; body: string }, jwk: PublicJwk) =>
  verifyRequestSignature({ method: "POST", path: "/api/v1/tokens/validate", authority: "auth.daywalker.dev", headers: req.headers, body: req.body, publicKey: jwk, replayCheck: false });

describe("Key lifecycle API helpers", () => {
  it("register sends a slot and TTL, is idempotent, and surfaces Daywalker's error codes", async () => {
    const dw = fakeDaywalker();
    const key = await generateSigningKey();
    const params = { apiKey: API_KEY, domain: DOMAIN, publicJwk: key.publicJwk, instanceId: keySlotFor(key.publicJwk.kid), ttlSeconds: 3600, fetchFn: dw.fetch };
    const first = await registerPublicKey(params);
    assert.equal(first.status, 201);
    assert.equal(first.key?.instanceId, `dw-${key.publicJwk.kid}`);
    assert.ok(first.key!.expiresAt! > Date.now() / 1000 + 3500);
    assert.equal(dw.calls[0].body.ttlSeconds, 3600);
    assert.equal(dw.calls[0].authorization, `Bearer ${API_KEY}`);

    const again = await registerPublicKey(params);
    assert.deepEqual([again.ok, again.status], [true, 200]);

    for (let i = 0; i < 19; i++) {
      const k = await generateSigningKey();
      assert.equal((await registerPublicKey({ ...params, publicJwk: k.publicJwk, instanceId: keySlotFor(k.publicJwk.kid) })).ok, true);
    }
    const extra = await generateSigningKey();
    const full = await registerPublicKey({ ...params, publicJwk: extra.publicJwk, instanceId: keySlotFor(extra.publicJwk.kid) });
    assert.deepEqual([full.ok, full.status, full.code], [false, 409, "KEY_LIMIT_REACHED"]);
  });

  it("validates slot and TTL before sending, and refuses an answer about another key", async () => {
    const key = await generateSigningKey();
    const never = (async () => assert.fail("must not send")) as any;
    const base = { apiKey: API_KEY, domain: DOMAIN, publicJwk: key.publicJwk, fetchFn: never };
    assert.equal((await registerPublicKey({ ...base, instanceId: "bad slot!" })).ok, false);
    assert.equal((await registerPublicKey({ ...base, ttlSeconds: 60 })).ok, false);
    assert.equal((await registerPublicKey({ ...base, ttlSeconds: 2_592_001 })).ok, false);
    assert.equal((await registerPublicKey({ ...base, expiresAt: new Date(Date.now() - 1000) })).ok, false);
    assert.equal((await revokeSigningKey({ apiKey: API_KEY, keyId: "../../etc", fetchFn: never })).ok, false);
    assert.equal((await listSigningKeys({ apiKey: API_KEY, domain: "localhost", fetchFn: never })).ok, false);

    const other = await generateSigningKey();
    const liar = (async () => Response.json({ keyId: other.publicJwk.kid, domain: DOMAIN, status: "ACTIVE" }, { status: 201 })) as any;
    assert.equal((await registerPublicKey({ ...base, fetchFn: liar })).status, 502);
  });

  it("lists and revokes keys, refusing redirects with the API key", async () => {
    const dw = fakeDaywalker();
    const key = await generateSigningKey();
    await registerPublicKey({ apiKey: API_KEY, domain: DOMAIN, publicJwk: key.publicJwk, instanceId: keySlotFor(key.publicJwk.kid), fetchFn: dw.fetch });
    const listed = await listSigningKeys({ apiKey: API_KEY, domain: DOMAIN, fetchFn: dw.fetch });
    assert.deepEqual(listed.keys?.map((k) => [k.keyId, k.status]), [[key.publicJwk.kid, "ACTIVE"]]);
    assert.equal((await revokeSigningKey({ apiKey: API_KEY, keyId: key.publicJwk.kid, fetchFn: dw.fetch })).ok, true);
    assert.equal((await listSigningKeys({ apiKey: API_KEY, domain: DOMAIN, fetchFn: dw.fetch })).keys![0].status, "REVOKED");
    const missing = await revokeSigningKey({ apiKey: API_KEY, keyId: "nope", fetchFn: dw.fetch });
    assert.deepEqual([missing.status, missing.code], [404, "key_not_found"]);

    let init: RequestInit | undefined;
    const redirect = (async (_u: string, i: RequestInit) => ((init = i), new Response(null, { status: 302, headers: { location: "https://evil.example" } }))) as any;
    assert.match((await revokeSigningKey({ apiKey: API_KEY, keyId: "k1", fetchFn: redirect })).error!, /redirect/);
    assert.equal(init?.redirect, "manual");
  });
});

describe("Ephemeral signing keys", () => {
  const client = (fetch: typeof globalThis.fetch, extra: Record<string, unknown> = {}) =>
    new Daywalker({ env, apiKey: API_KEY, serviceSlug: "svc", domain: DOMAIN, ephemeralKey: { ttlSeconds: 3600, instanceId: "web-1" }, fetch, ...extra });

  it("registers an in-memory key in this process's slot with a TTL, and signs with it", async () => {
    const dw = fakeDaywalker();
    const dwClient = client(dw.fetch);
    assert.equal((await dwClient.validateToken("tok")).ok, true);
    const [key] = [...dw.keys.values()];
    assert.equal(key.instanceId, "web-1");
    assert.ok(key.expiresAt! > Date.now() / 1000 + 3500);
    assert.equal((await verifyWith(dw.validated[0], key.jwk)).valid, true);
    assert.deepEqual(await dwClient.provisionSigningKey(), { source: "ephemeral", keyId: key.keyId });
    assert.equal((await dwClient.selfCheck()).keyId, key.keyId);
  });

  it("a restart with the same slot replaces the previous key instead of adding one", async () => {
    const dw = fakeDaywalker();
    await client(dw.fetch).provisionSigningKey();
    await client(dw.fetch).provisionSigningKey();
    const statuses = [...dw.keys.values()].map((k) => k.status);
    assert.deepEqual(statuses, ["ROTATING", "ACTIVE"]);
  });

  it("rotates in the same slot before expiry, then starts a new OAuth session with the new key", async () => {
    let registrations = 0;
    const tokenLog: TokenRequestLog[] = [];
    (globalThis as any).__tokenLog = tokenLog;
    try {
      // The first key expires in 2 minutes: still usable, but due for replacement (under a quarter of the hour
      // left), so it is replaced in the background after the first grant. Later keys live an hour.
      const dw = fakeDaywalker({ expiresIn: () => Math.floor(Date.now() / 1000) + (registrations++ === 0 ? 120 : 3600) });
      const dwClient = client(dw.fetch);
      assert.equal((await dwClient.validateToken("a")).ok, true);
      await new Promise((r) => setTimeout(r, 20)); // let the background replacement finish
      assert.equal((await dwClient.validateToken("b")).ok, true);
      const [first, second, ...rest] = [...dw.keys.values()];
      assert.equal(rest.length, 0);
      assert.deepEqual([first.status, second.status, first.instanceId, second.instanceId], ["ROTATING", "ACTIVE", "web-1", "web-1"]);
      assert.equal((await verifyWith(dw.validated.at(-1)!, second.jwk)).valid, true);
      // The grant made with the first key is dropped once it is replaced; the next grant uses the new key.
      assert.deepEqual(tokenLog.map((r) => r.grantType), ["client_credentials", "client_credentials"]);
    } finally {
      delete (globalThis as any).__tokenLog;
    }
  });

  it("keeps signing with a still-valid key when a background replacement fails, without retrying every request", async () => {
    let fail = false;
    const dw = fakeDaywalker({
      expiresIn: () => Math.floor(Date.now() / 1000) + 600, // valid, but due for replacement (under a quarter of 3600 left)
      failRegister: () => (fail ? Response.json({ error: "internal_error", message: "down" }, { status: 503 }) : null),
    });
    const dwClient = client(dw.fetch);
    await dwClient.provisionSigningKey();
    fail = true;
    for (const t of ["a", "b", "c"]) assert.equal((await dwClient.validateToken(t)).ok, true);
    await new Promise((r) => setTimeout(r, 20));
    const attempts = dw.calls.filter((c) => c.path === "/api/v1/keys/register").length;
    assert.equal(attempts, 2); // the first registration, then one failed replacement: retried after 30s, not per request
    const [key] = [...dw.keys.values()];
    assert.equal((await verifyWith(dw.validated.at(-1)!, key.jwk)).valid, true);
  });

  it("explains a full domain", async () => {
    const dw = fakeDaywalker({ failRegister: () => Response.json({ error: "KEY_LIMIT_REACHED", message: "Maximum limit of 20" }, { status: 409 }) });
    const res = await client(dw.fetch).validateToken("tok");
    assert.equal(res.ok ? null : res.status, 503);
    assert.match(res.ok ? "" : res.message, /KEY_LIMIT_REACHED.*daywalker keys.*daywalker revoke/);
  });

  it("close() revokes the key and refuses further use", async () => {
    const dw = fakeDaywalker();
    const dwClient = client(dw.fetch);
    const { keyId } = (await dwClient.provisionSigningKey())!;
    assert.deepEqual(await dwClient.close(), { revoked: [keyId], failed: [] });
    assert.equal(dw.keys.get(keyId)!.status, "REVOKED");
    assert.deepEqual(await dwClient.close(), { revoked: [], failed: [] });
    const after = await dwClient.validateToken("tok");
    assert.match(after.ok ? "" : after.message, /closed/);
    await assert.rejects(dwClient.provisionSigningKey(), /closed/);
  });

  it("is configured from the environment, validated, and exclusive with keyStore", async () => {
    const dw = fakeDaywalker();
    const fromEnv = new Daywalker({ env: { DAYWALKER_EPHEMERAL_KEY: "true", DAYWALKER_KEY_TTL_SECONDS: "7200", DAYWALKER_INSTANCE_ID: "pod-a", DAYWALKER_API_KEY: API_KEY, DAYWALKER_DOMAIN: DOMAIN }, fetch: dw.fetch });
    await fromEnv.provisionSigningKey();
    const [key] = [...dw.keys.values()];
    assert.equal(key.instanceId, "pod-a");
    assert.ok(key.expiresAt! > Date.now() / 1000 + 7100);
    const random = new Daywalker({ env, apiKey: API_KEY, domain: DOMAIN, ephemeralKey: true, fetch: dw.fetch });
    await random.provisionSigningKey();
    assert.match([...dw.keys.values()][1].instanceId!, /^dw-i-[0-9a-f]{24}$/);

    assert.throws(() => new Daywalker({ env, ephemeralKey: { ttlSeconds: 60 } }), /ttlSeconds/);
    assert.throws(() => new Daywalker({ env, ephemeralKey: { instanceId: "bad slot!" } }), /instanceId/);
    assert.throws(() => new Daywalker({ env, ephemeralKey: true, keyStore: memoryKeyStore() }), /either keyStore or ephemeralKey/);
  });
});

describe("CLI key commands", { skip: process.platform === "win32" }, () => {
  const CLI = path.resolve("src/cli.ts");
  const TSX = path.resolve("node_modules/tsx/dist/esm/index.mjs");

  async function withServer(fn: (authUrl: string, seen: { method: string; url: string; body: any }[]) => Promise<void>) {
    const seen: { method: string; url: string; body: any }[] = [];
    const server = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        seen.push({ method: req.method!, url: req.url!, body: raw ? JSON.parse(raw) : null });
        res.setHeader("content-type", "application/json");
        if (req.url!.startsWith("/api/v1/keys/register")) return res.end(JSON.stringify({ keyId: JSON.parse(raw).keyId, domain: DOMAIN, status: "ACTIVE" }));
        if (req.method === "GET") return res.end(JSON.stringify({ keys: [{ keyId: "k_current", domain: DOMAIN, status: "ACTIVE", instanceId: "dw-k_current", expiresAt: null, createdAt: "2026-10-18T00:00:00Z", lastUsedAt: null }] }));
        if (req.method === "DELETE") return res.end(JSON.stringify({ success: true }));
        res.statusCode = 404;
        res.end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    try {
      await fn(`http://127.0.0.1:${(server.address() as AddressInfo).port}`, seen);
    } finally {
      server.close();
    }
  }

  const run = (cwd: string, args: string[], extraEnv: Record<string, string>) =>
    new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const clean: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("DAYWALKER_") && v !== undefined) clean[k] = v;
      const child = spawn(process.execPath, ["--import", TSX, CLI, ...args], { cwd, env: { ...clean, ...extraEnv } });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
      child.on("error", reject);
      child.on("close", (status) => resolve({ status, stdout, stderr }));
      child.stdin.end("");
    });

  it("lists keys, refuses to revoke the current key without --force, and registers init keys in their own slot", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-keys-"));
    try {
      await withServer(async (authUrl, seen) => {
        const e = { DAYWALKER_API_KEY: API_KEY, DAYWALKER_DOMAIN: DOMAIN, DAYWALKER_AUTH_URL: authUrl, DAYWALKER_KEY_ID: "k_current" };
        const list = await run(dir, ["keys"], e);
        assert.equal(list.status, 0, list.stderr);
        assert.match(list.stdout, /k_current \(current\)\s+ACTIVE\s+slot=dw-k_current/);

        const refused = await run(dir, ["revoke", "k_current"], e);
        assert.equal(refused.status, 1);
        assert.match(refused.stderr, /--force/);
        assert.equal(seen.filter((s) => s.method === "DELETE").length, 0);

        const ok = await run(dir, ["revoke", "k_old"], e);
        assert.equal(ok.status, 0, ok.stderr);
        assert.ok(seen.some((s) => s.method === "DELETE" && s.url === "/api/v1/keys/k_old"));

        const init = await run(dir, ["init", "--domain", DOMAIN, "--auth-url", authUrl], { DAYWALKER_API_KEY: API_KEY });
        assert.equal(init.status, 0, init.stderr);
        const reg = seen.find((s) => s.url === "/api/v1/keys/register")!;
        assert.equal(reg.body.instanceId, `dw-${reg.body.keyId}`);
      });
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
