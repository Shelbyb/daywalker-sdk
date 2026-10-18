import { describe, it, type TestContext } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Daywalker, JWKS_CACHE_TTL_MS, JWKS_REFETCH_COOLDOWN_MS } from "../src/index.js";
import { withOAuth } from "./helpers/oauth.js";

const env = {};
const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

function issuer(kid: string) {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const jwk = { ...(crypto.createPublicKey(privateKey).export({ format: "jwk" }) as Record<string, unknown>), kid, use: "sig", alg: "EdDSA" };
  const sign = (claims: Record<string, unknown> = {}, header: Record<string, unknown> = { kid }) => {
    const h = enc({ alg: "EdDSA", typ: "at+jwt", ...header });
    const b = enc({ iss: "https://auth.daywalker.dev", aud: ["svc"], services: ["svc"], jti: crypto.randomUUID(), exp: now() + 300, sub: "u1", ...claims });
    return `${h}.${b}.${crypto.sign(null, Buffer.from(`${h}.${b}`), privateKey).toString("base64url")}`;
  };
  return { kid, jwk, sign };
}

/**
 * A Daywalker Auth stand-in: GET /.well-known/jwks.json answers with `jwks()` (a Response is sent as is),
 * POST /api/v1/tokens/validate rejects every token, and every requested URL is logged.
 */
function server(jwks: () => unknown, tokenResponse?: () => Response) {
  const urls: string[] = [];
  const jwksFetches = () => urls.filter((u) => u.endsWith("/.well-known/jwks.json")).length;
  const validations = () => urls.filter((u) => u.endsWith("/api/v1/tokens/validate")).length;
  const fetch = withOAuth(
    async (url) => {
      const href = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
      urls.push(href);
      if (new URL(href).pathname === "/.well-known/jwks.json") {
        const body = jwks();
        return body instanceof Response ? body : Response.json(body);
      }
      return Response.json({ valid: false, error: "INVALID_TOKEN" }, { status: 401 });
    },
    { tokenResponse }
  );
  const logged: typeof globalThis.fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const href = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
    if (new URL(href).pathname === "/api/v1/oauth/token") urls.push(href);
    return fetch(url, init);
  }) as typeof globalThis.fetch;
  return { fetch: logged, urls, jwksFetches, validations };
}

const client = (fetch: typeof globalThis.fetch, extra: Record<string, unknown> = {}) =>
  new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", jwks: "auto", fetch, negativeCacheTtlMs: 0, cacheTtlMs: 0, ...extra });

const mockClock = (t: TestContext) => t.mock.timers.enable({ apis: ["Date"], now: Date.now() });

describe("offline verification against Daywalker's JWKS (jwks: \"auto\")", () => {
  it("verifies offline from the fetched set and caches it", async () => {
    const a = issuer("key-a");
    const srv = server(() => ({ keys: [a.jwk] }));
    const dw = client(srv.fetch);
    for (let i = 0; i < 5; i++) {
      const res = await dw.validateToken(a.sign(), { offlineOnly: true });
      assert.equal(res.ok && res.data.offlineVerified, true);
    }
    assert.equal(srv.jwksFetches(), 1);
    assert.equal(srv.validations(), 0);
    assert.equal(Object.isFrozen(dw), true);
    assert.equal((await dw.selfCheck()).offlineVerificationReady, true);
  });

  it("is turned on by DAYWALKER_JWKS=auto", async () => {
    const a = issuer("key-a");
    const srv = server(() => ({ keys: [a.jwk] }));
    const dw = new Daywalker({ env: { DAYWALKER_JWKS: "auto" }, serviceSlug: "svc", fetch: srv.fetch });
    assert.equal(dw.config.jwks, "auto");
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);
  });

  it("picks up a rotated key under a new kid, and refetches an expired set", async (t) => {
    mockClock(t);
    const a = issuer("key-a");
    const b = issuer("key-b");
    let keys = [a.jwk];
    const srv = server(() => ({ keys }));
    const dw = client(srv.fetch);
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);

    // Daywalker rotates to key-b (keeping key-a published for a while)
    keys = [a.jwk, b.jwk];
    t.mock.timers.tick(JWKS_REFETCH_COOLDOWN_MS);
    const res = await dw.validateToken(b.sign(), { offlineOnly: true });
    assert.equal(res.ok && res.data.offlineVerified, true);
    assert.equal(srv.jwksFetches(), 2);

    // key-a is retired: once the cached set expires, it stops verifying
    keys = [b.jwk];
    t.mock.timers.tick(JWKS_CACHE_TTL_MS);
    const retired = await dw.validateToken(a.sign(), { offlineOnly: true });
    assert.equal(retired.ok, false);
    assert.equal(srv.jwksFetches(), 3);
    assert.equal((await dw.validateToken(b.sign(), { offlineOnly: true })).ok, true);
    assert.equal(srv.jwksFetches(), 3);
  });

  it("refetches for an unknown kid at most once per cooldown", async (t) => {
    mockClock(t);
    const a = issuer("key-a");
    const srv = server(() => ({ keys: [a.jwk] }));
    const dw = client(srv.fetch);
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);
    t.mock.timers.tick(JWKS_REFETCH_COOLDOWN_MS);

    // A flood of tokens naming made-up kids, sequential and concurrent
    const forger = issuer("x");
    const forged = () => forger.sign({}, { kid: crypto.randomUUID() });
    for (let i = 0; i < 10; i++) assert.equal((await dw.validateToken(forged(), { offlineOnly: true })).ok, false);
    const burst = await Promise.all(Array.from({ length: 20 }, () => dw.validateToken(forged(), { offlineOnly: true })));
    assert.ok(burst.every((r) => !r.ok));
    assert.equal(srv.jwksFetches(), 2);

    t.mock.timers.tick(JWKS_REFETCH_COOLDOWN_MS - 1);
    await dw.validateToken(forged(), { offlineOnly: true });
    assert.equal(srv.jwksFetches(), 2);
    t.mock.timers.tick(1);
    await dw.validateToken(forged(), { offlineOnly: true });
    assert.equal(srv.jwksFetches(), 3);
    // Known keys keep verifying throughout
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);
  });

  it("keeps the last good set when a refresh fails or has no usable key", async (t) => {
    mockClock(t);
    const a = issuer("key-a");
    let answer: () => unknown = () => ({ keys: [a.jwk] });
    const srv = server(() => answer());
    const dw = client(srv.fetch);
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);

    const failures: Array<() => unknown> = [
      () => new Response("down", { status: 503 }),
      () => new Response("not json", { status: 200 }),
      () => new Response(null, { status: 302, headers: { location: "https://evil.example/jwks.json" } }),
      () => ({ keys: [] }),
      () => ({ keys: [{ kty: "RSA", kid: "key-a", n: "AQAB", e: "AQAB" }] }),
      () => {
        throw new TypeError("fetch failed");
      },
    ];
    for (const failure of failures) {
      answer = failure;
      t.mock.timers.tick(JWKS_CACHE_TTL_MS);
      const res = await dw.validateToken(a.sign(), { offlineOnly: true });
      assert.equal(res.ok && res.data.offlineVerified, true);
    }
    assert.equal(srv.jwksFetches(), 1 + failures.length);
    assert.ok(srv.urls.every((u) => new URL(u).host === "auth.daywalker.dev"));
  });

  it("only accepts EdDSA / Ed25519 signing keys from the set", async () => {
    const a = issuer("key-a");
    const { alg: _alg, ...noAlg } = a.jwk as Record<string, unknown>;
    for (const bad of [
      { ...a.jwk, alg: "ES256" },
      { ...a.jwk, alg: "none" },
      { ...a.jwk, use: "enc" },
      { ...a.jwk, crv: "X25519" },
      { ...a.jwk, kid: undefined },
      { ...a.jwk, x: "AAAA" },
    ]) {
      const srv = server(() => ({ keys: [bad] }));
      const res = await client(srv.fetch).validateToken(a.sign(), { offlineOnly: true });
      assert.equal(res.ok, false, JSON.stringify(bad));
    }
    // alg and use are optional
    const srv = server(() => ({ keys: [noAlg] }));
    assert.equal((await client(srv.fetch).validateToken(a.sign(), { offlineOnly: true })).ok, true);
  });

  it("never fetches a jwks_uri on another host, only ${authUrl}/.well-known/jwks.json", async () => {
    const a = issuer("key-a");
    const tokenResponse = () =>
      Response.json({
        access_token: a.sign(),
        token_type: "DPoP",
        expires_in: 900,
        refresh_token: "rt_1",
        services: ["svc"],
        jwks_uri: "https://evil.example/.well-known/jwks.json",
      });
    const srv = server(() => ({ keys: [a.jwk], jwks_uri: "https://evil.example/jwks.json" }), tokenResponse);
    const dw = client(srv.fetch, { authUrl: "https://auth.example.com" });
    // Opaque token: online validation, which runs the client credentials grant
    await dw.validateToken("dw_opaque_token");
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);
    assert.equal(srv.validations(), 1);
    assert.deepEqual(new Set(srv.urls.map((u) => new URL(u).origin)), new Set(["https://auth.example.com"]));
    assert.deepEqual(
      srv.urls.filter((u) => u.includes("jwks")),
      ["https://auth.example.com/.well-known/jwks.json"]
    );
  });

  it("fails closed when no key set can be obtained", async () => {
    const a = issuer("key-a");
    const srv = server(() => new Response("down", { status: 503 }));
    const dw = client(srv.fetch);
    const offline = await dw.validateToken(a.sign(), { offlineOnly: true });
    assert.deepEqual(offline.ok ? null : [offline.status, offline.error], [503, "SERVICE_UNAVAILABLE"]);
    // Without offlineOnly the token goes to Daywalker instead (which rejects it here)
    const online = await dw.validateToken(a.sign());
    assert.equal(online.ok, false);
    assert.equal(srv.validations(), 1);
  });

  it("uses the static daywalkerPublicKey while the JWKS can't be fetched", async () => {
    const a = issuer("key-a");
    const srv = server(() => new Response("down", { status: 503 }));
    const dw = client(srv.fetch, { daywalkerPublicKey: a.jwk });
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);
    assert.equal(srv.jwksFetches(), 1);
  });

  it("leaves the static key path alone when jwks is off", async () => {
    const a = issuer("key-a");
    const srv = server(() => ({ keys: [a.jwk] }));
    const dw = client(srv.fetch, { jwks: "off", daywalkerPublicKey: a.jwk });
    assert.equal((await dw.validateToken(a.sign(), { offlineOnly: true })).ok, true);
    assert.equal(srv.jwksFetches(), 0);
    const none = client(srv.fetch, { jwks: undefined });
    const res = await none.validateToken(a.sign(), { offlineOnly: true });
    assert.deepEqual(res.ok ? null : res.error, "CONFIGURATION_ERROR");
    assert.equal(srv.jwksFetches(), 0);
  });
});
