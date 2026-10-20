import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Daywalker, daywalker, registerPublicKey, sha256Base64Url, verifyJwtLease, generateSigningKey } from "../src/index.js";
import { createDpopProof, generateDpopKey, verifyDpopProof, type DpopKey } from "../src/crypto/dpop.js";
import { createDaywalkerMiddleware, withDaywalkerAuth } from "../src/next.js";
import { daywalkerAuth as webAuth, readCredentials } from "../src/middleware.js";
import { daywalkerAuth as expressAuth } from "../src/express.js";
import { withOAuth } from "./helpers/oauth.js";

const env = {};
const { privateKey: issuerKey } = crypto.generateKeyPairSync("ed25519");
const issuerJwk = crypto.createPublicKey(issuerKey).export({ format: "jwk" }) as any;
const enc = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");
const now = () => Math.floor(Date.now() / 1000);

function accessToken(claims: Record<string, unknown> = {}): string {
  const h = enc({ alg: "EdDSA", typ: "at+jwt" });
  const b = enc({ iss: "https://auth.daywalker.dev", aud: ["svc"], services: ["svc"], jti: crypto.randomUUID(), exp: now() + 300, sub: "u1", ...claims });
  return `${h}.${b}.${crypto.sign(null, Buffer.from(`${h}.${b}`), issuerKey).toString("base64url")}`;
}

async function jktOf(key: DpopKey): Promise<string> {
  return sha256Base64Url(JSON.stringify({ crv: "Ed25519", kty: "OKP", x: key.publicJwk.x }));
}

const offlineClient = (extra: Record<string, unknown> = {}) =>
  new Daywalker({ env, serviceSlug: "svc", daywalkerPublicKey: issuerJwk, fetch: withOAuth(async () => Response.json({})), ...extra });

describe("DPoP-bound access tokens (RFC 9449) are useless without the client's key", () => {
  it("refuses a bound token presented as a bearer token", async () => {
    const key = await generateDpopKey();
    const token = accessToken({ cnf: { jkt: await jktOf(key) } });
    const res = await offlineClient().validateToken(token);
    assert.deepEqual(res.ok ? null : [res.status, res.error], [401, "DPOP_REQUIRED"]);
  });

  it("accepts it with a fresh proof, and refuses a replayed, misdirected or foreign proof, cached or not", async () => {
    const key = await generateDpopKey();
    const token = accessToken({ cnf: { jkt: await jktOf(key) } });
    const client = offlineClient();
    const url = "https://app.example.com/api/data?x=1";
    const proof = await createDpopProof(key, { method: "GET", url, accessToken: token });

    const ok = await client.validateToken(token, { dpop: { proof, method: "GET", url } });
    assert.equal(ok.ok, true);
    // Same proof again (now served from the cache): replay
    const replay = await client.validateToken(token, { dpop: { proof, method: "GET", url } });
    assert.deepEqual(replay.ok ? null : replay.error, "INVALID_DPOP_PROOF");
    // Cached token, no proof at all
    const bare = await client.validateToken(token);
    assert.deepEqual(bare.ok ? null : bare.error, "DPOP_REQUIRED");
    // Proof made for another endpoint or method
    const other = await createDpopProof(key, { method: "GET", url: "https://app.example.com/api/other", accessToken: token });
    const misdirected = await client.validateToken(token, { dpop: { proof: other, method: "GET", url } });
    assert.match(misdirected.ok ? "" : misdirected.message, /htu/);
    const wrongMethod = await createDpopProof(key, { method: "POST", url, accessToken: token });
    assert.match(((await client.validateToken(token, { dpop: { proof: wrongMethod, method: "GET", url } })) as any).message, /htm/);
    // A thief's own key
    const thief = await generateDpopKey();
    const forged = await createDpopProof(thief, { method: "GET", url, accessToken: token });
    assert.match(((await client.validateToken(token, { dpop: { proof: forged, method: "GET", url } })) as any).message, /cnf\.jkt/);
    // A proof for a different access token
    const otherAth = await createDpopProof(key, { method: "GET", url, accessToken: accessToken() });
    assert.match(((await client.validateToken(token, { dpop: { proof: otherAth, method: "GET", url } })) as any).message, /ath/);
  });

  it("never lets a non-finite maxAgeSeconds or currentTime switch off the proof's iat freshness check", async () => {
    const key = await generateDpopKey();
    const token = accessToken();
    const url = "https://app.example.com/api/data";
    const expectedJkt = await jktOf(key);
    const base = { method: "GET", url, accessToken: token, expectedJkt };
    const stale = await createDpopProof(key, { method: "GET", url, accessToken: token });
    for (const maxAgeSeconds of [NaN, Infinity, -Infinity]) {
      const res = await verifyDpopProof({ ...base, proof: stale, currentTime: now() + 3600, maxAgeSeconds });
      assert.match(res.valid ? "" : res.error!, /iat/);
    }
    const fresh = await createDpopProof(key, { method: "GET", url, accessToken: token });
    assert.equal((await verifyDpopProof({ ...base, proof: fresh, currentTime: NaN, maxAgeSeconds: NaN })).valid, true);
  });

  it("checks htu against publicOrigin when the app sits behind a proxy", async () => {
    const key = await generateDpopKey();
    const token = accessToken({ cnf: { jkt: await jktOf(key) } });
    const client = offlineClient({ publicOrigin: "https://api.example.com" });
    const proof = await createDpopProof(key, { method: "GET", url: "https://api.example.com/v1/x", accessToken: token });
    const res = await client.validateToken(token, { dpop: { proof, method: "GET", url: "http://10.0.0.5:3000/v1/x" } });
    assert.equal(res.ok, true);
  });

  it("works end to end through the Next middleware with Authorization: DPoP", async () => {
    const key = await generateDpopKey();
    const token = accessToken({ cnf: { jkt: await jktOf(key) } });
    const mw = createDaywalkerMiddleware({ client: offlineClient() });
    const url = "https://app.example.com/api/data";
    const proof = await createDpopProof(key, { method: "GET", url, accessToken: token });
    const ok = await mw(new Request(url, { headers: { authorization: `DPoP ${token}`, dpop: proof } }));
    assert.equal(ok.headers.get("x-middleware-next"), "1");
    const asBearer = await mw(new Request(url, { headers: { authorization: `Bearer ${token}` } }));
    assert.equal(asBearer.status, 401);
    assert.equal((await asBearer.json()).error, "DPOP_REQUIRED");
  });
});

describe("Tokens for a sibling service are refused", () => {
  it("rejects an online answer that validated the token for another service", async () => {
    const client = new Daywalker({
      env,
      apiKey: "srv_live_service_key",
      serviceSlug: "devpulse",
      fetch: withOAuth(async () => Response.json({ valid: true, serviceSlug: "gigpulse", services: ["gigpulse"], tenantId: "t" }), { services: ["devpulse"] }),
    });
    const res = await client.validateToken("srv_live_gigpulse_token");
    assert.deepEqual(res.ok ? null : [res.status, res.error], [403, "SERVICE_NOT_GRANTED"]);
  });

  it("fails closed when the answer names no service", async () => {
    const client = new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", fetch: withOAuth(async () => Response.json({ valid: true, tenantId: "t" })) });
    const res = await client.validateToken("tok");
    assert.deepEqual(res.ok ? null : [res.status, res.error], [503, "SERVICE_UNAVAILABLE"]);
  });

  it("narrows the client credentials grant to the configured services by default", async () => {
    const bodies: string[] = [];
    const client = new Daywalker({
      env,
      apiKey: "srv_live_service_key",
      serviceSlug: "devpulse",
      fetch: (async (_u: string, init: RequestInit) => {
        bodies.push(String(init.body));
        return withOAuth(async () => Response.json({}), { services: ["devpulse"] })(_u, init);
      }) as typeof fetch,
    });
    await client.getTokens();
    assert.equal(JSON.parse(bodies[0]).scope, "devpulse");
  });
});

describe("Tamper resistance inside the process", () => {
  it("can't be patched through the class, an instance or the default client", () => {
    const client = new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc" });
    assert.throws(() => {
      (Daywalker.prototype as any).validateToken = async () => ({ ok: true });
    }, TypeError);
    assert.throws(() => {
      (client as any).validateToken = async () => ({ ok: true });
    }, TypeError);
    assert.throws(() => {
      (client as any).fetch = async () => Response.json({ valid: true });
    }, TypeError);
    assert.throws(() => {
      (daywalker as any).validateToken = async () => ({ ok: true });
    }, TypeError);
    assert.ok(Object.isFrozen(Daywalker.prototype));
  });

  it("hands out a frozen, secret-free config, and ignores later changes to the options object", async () => {
    const options: Record<string, any> = { env, apiKey: "srv_live_service_key", serviceSlug: "svc", authUrl: "https://auth.daywalker.dev" };
    const seen: string[] = [];
    options.fetch = withOAuth(async (u) => (seen.push(String(u)), Response.json({ valid: true, serviceSlug: "svc" })));
    const client = new Daywalker(options);
    assert.equal(client.config.apiKey, "[configured]");
    assert.ok(Object.isFrozen(client.config) && Object.isFrozen(client.config.serviceSlugs));
    assert.equal(JSON.stringify(client).includes("srv_live_service_key"), false);
    options.authUrl = "https://evil.example";
    options.fetch = async () => Response.json({ valid: true, serviceSlug: "svc" });
    await client.validateToken("tok");
    assert.ok(seen[0].startsWith("https://auth.daywalker.dev/"));
  });

  it("keeps verifying signatures after crypto.subtle.verify is replaced", async () => {
    const forged = accessToken().replace(/\.[^.]+$/, `.${Buffer.alloc(64).toString("base64url")}`);
    const original = crypto.webcrypto.subtle.verify;
    (globalThis.crypto.subtle as any).verify = async () => true;
    try {
      const res = await verifyJwtLease({ token: forged, publicKey: issuerJwk, expectedServiceSlug: "svc" });
      assert.equal(res.valid, false);
    } finally {
      (globalThis.crypto.subtle as any).verify = original;
    }
  });

  it("ignores a NextResponse planted on globalThis", async () => {
    (globalThis as any).NextResponse = { next: () => new Response("pwned"), redirect: () => new Response(null, { headers: { "x-middleware-next": "1" } }) };
    try {
      const client = new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", fetch: withOAuth(async () => Response.json({ valid: false, message: "revoked" }, { status: 401 })) });
      const res = await createDaywalkerMiddleware({ client })(new Request("https://app.example.com/dashboard", { headers: { authorization: "Bearer tok" } }));
      assert.equal(res.status, 307);
      assert.equal(res.headers.get("x-middleware-next"), null);
    } finally {
      delete (globalThis as any).NextResponse;
    }
  });

  it("generates a DPoP key whose private half can't be exported", async () => {
    const key = await generateDpopKey();
    assert.equal(key.privateKey.extractable, false);
    await assert.rejects(crypto.webcrypto.subtle.exportKey("jwk", key.privateKey as any));
  });
});

describe("Token endpoint answers are checked before they are trusted", () => {
  const withToken = (body: Record<string, unknown>) =>
    new Daywalker({
      env,
      apiKey: "srv_live_service_key",
      fetch: withOAuth(async () => Response.json({}), { tokenResponse: () => Response.json(body) }),
    });

  it("refuses an unbound (Bearer) token and malformed tokens", async () => {
    const base = { access_token: "eyJ.a.b", refresh_token: "rt_1", expires_in: 900, services: ["svc"] };
    await assert.rejects(withToken({ ...base, token_type: "Bearer" }).getTokens(), /token_type is not DPoP/);
    await assert.rejects(withToken({ ...base, token_type: "DPoP", access_token: "a b" }).getTokens(), /malformed/);
    await assert.rejects(withToken({ ...base, token_type: "DPoP", expires_in: -1 }).getTokens(), /expires_in/);
  });

  it("caps the access token lifetime whatever expires_at says, and freezes the result", async () => {
    const tokens = await withToken({ access_token: "eyJ.a.b", refresh_token: "rt_1", token_type: "DPoP", expires_in: 900, expires_at: 9_999_999_999, services: ["svc", "BAD SLUG"] }).getTokens();
    assert.ok(tokens.expiresAt <= now() + 900);
    assert.deepEqual(tokens.services, ["svc"]);
    assert.ok(Object.isFrozen(tokens));
  });

  it("refuses an oversized response body", async () => {
    const client = new Daywalker({
      env,
      apiKey: "srv_live_service_key",
      fetch: withOAuth(async () => Response.json({}), { tokenResponse: () => new Response("x".repeat(2_000_000), { status: 200 }) }),
    });
    await assert.rejects(client.getTokens(), /too large|larger than/);
  });
});

describe("Inputs are bounded and well-formed before anything is sent", () => {
  it("rejects oversized or malformed tokens without calling Daywalker", async () => {
    let calls = 0;
    const client = new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", fetch: withOAuth(async () => (calls++, Response.json({ valid: true, serviceSlug: "svc" }))) });
    for (const bad of ["a".repeat(9000), "tok en", "tok\r\nx", "tok,other", '"tok"', "tök"]) {
      const res = await client.validateToken(bad);
      assert.deepEqual(res.ok ? null : [res.status, res.error], [401, "INVALID_TOKEN"], JSON.stringify(bad.slice(0, 20)));
    }
    assert.equal(calls, 0);
    assert.equal(((await client.validateToken(42 as any)) as any).error, "INVALID_TOKEN");
  });

  it("reads credentials strictly: unknown schemes and repeated headers are refused, not skipped", () => {
    const req = { method: "GET", url: "https://a.example/x" };
    const from = (h: Record<string, string | string[]>) => readCredentials((n) => h[n], req);
    assert.equal(from({ authorization: "Basic dXNlcjpwYXNz", "x-api-token": "tok" }).ok, false);
    assert.equal(from({ authorization: "Bearer a b" }).ok, false);
    assert.equal(from({ "x-api-token": ["a", "b"] }).ok, false);
    assert.equal(from({ authorization: `Bearer ${"a".repeat(9000)}` }).ok, false);
    assert.deepEqual(from({ authorization: "bearer tok" }), { ok: true, token: "tok" });
    assert.deepEqual(from({ "x-api-token": " tok " }), { ok: true, token: "tok" });
    const d = from({ authorization: "DPoP tok", dpop: "proof" });
    assert.ok(d.ok && d.dpop?.proof === "proof" && d.dpop.method === "GET");
  });

  it("applies the same rules in the Web, Express and route-handler adapters", async () => {
    let calls = 0;
    const client = new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", fetch: withOAuth(async () => (calls++, Response.json({ valid: true, serviceSlug: "svc" }))) });
    const web = (await webAuth({ client })({ req: { raw: new Request("https://a.example/x", { headers: { authorization: "Basic x", "x-api-token": "tok" } }) } }, async () => undefined)) as Response;
    assert.equal(web.status, 401);
    let status = 0;
    const res = { setHeader() {}, status(c: number) { status = c; return res; }, json() {}, end() {} };
    await expressAuth({ client })({ method: "GET", url: "/x", headers: { authorization: "Basic x", "x-api-token": "tok" } }, res as any);
    assert.equal(status, 401);
    const handler = withDaywalkerAuth(async () => new Response("ok"), client);
    assert.equal((await handler(new Request("https://a.example/x", { headers: { authorization: "Token tok" } }))).status, 401);
    assert.equal(calls, 0);
  });

  it("caps cacheTtlMs so a revoked token can't stay accepted for long", () => {
    assert.equal(new Daywalker({ env, cacheTtlMs: 86_400_000 }).config.cacheTtlMs, 300_000);
    assert.throws(() => new Daywalker({ env, authUrl: "https://user:pass@auth.example.com" }), /credentials/);
  });
});

describe("Key registration never leaks the API key", () => {
  const base = { apiKey: "srv_live_register_key", domain: "app.example.com" };

  it("refuses redirects instead of following them with the key", async () => {
    const key = await generateSigningKey();
    let init: RequestInit | undefined;
    const res = await registerPublicKey({
      ...base,
      publicJwk: key.publicJwk,
      fetchFn: (async (_u: string, i: RequestInit) => ((init = i), new Response(null, { status: 307, headers: { location: "https://evil.example/" } }))) as any,
    });
    assert.equal(res.ok, false);
    assert.match(res.error!, /redirect/);
    assert.equal(init?.redirect, "manual");
    assert.equal(init?.cache, "no-store");
    assert.ok(init?.signal);
  });

  it("validates the domain, the key and the API key first", async () => {
    const key = await generateSigningKey();
    const never = (async () => assert.fail("must not send")) as any;
    assert.equal((await registerPublicKey({ ...base, domain: "localhost", publicJwk: key.publicJwk, fetchFn: never })).ok, false);
    assert.equal((await registerPublicKey({ ...base, apiKey: "bad key\r\nX-Evil: 1", publicJwk: key.publicJwk, fetchFn: never })).ok, false);
    const priv = { ...key.publicJwk, d: "secret" } as any;
    assert.match((await registerPublicKey({ ...base, publicJwk: priv, fetchFn: never })).error!, /never a private key/);
    assert.equal((await registerPublicKey({ ...base, serviceSlug: "bad slug!", publicJwk: key.publicJwk, fetchFn: never })).ok, false);
  });
});
