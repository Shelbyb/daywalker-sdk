import { describe, it } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import {
  Daywalker,
  SignatureReplayCache,
  base64UrlToBytesStrict,
  createSignatureBase,
  generateSigningKey,
  loadPublicKey,
  signRequest,
  verifyJwtLease,
  verifyRequestSignature,
  type ReplayStore,
} from "../src/index.js";
import { normalizePath, splitRequestTarget } from "../src/crypto/signatures.js";

type MockFetch = (url: string, init: RequestInit) => Promise<Response>;
const env = {};
const client = (fetch: MockFetch, extra: Record<string, unknown> = {}) =>
  new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", fetch: fetch as typeof globalThis.fetch, ...extra });

describe("Online validation fails closed", () => {
  for (const [name, res] of [
    ["a 200 HTML page", () => new Response("<html>captive portal</html>", { status: 200 })],
    ["a 200 empty object", () => Response.json({})],
    ["a 200 array", () => Response.json([{ valid: true }])],
    ["valid: 'true' (string)", () => Response.json({ valid: "true", tenantId: "t" })],
    ["valid: true with a bad rateLimit", () => Response.json({ valid: true, rateLimit: "lots" })],
    ["valid: true with a non-string tenantId", () => Response.json({ valid: true, tenantId: { admin: true } })],
    ["valid: true with array data", () => Response.json({ valid: true, data: [] })],
  ] as const) {
    it(`rejects ${name} with SERVICE_UNAVAILABLE and never caches it`, async () => {
      let calls = 0;
      const dw = client(async () => (calls++, res()));
      const a = await dw.validateToken("tok");
      assert.deepStrictEqual([a.ok, !a.ok && a.error, !a.ok && a.status], [false, "SERVICE_UNAVAILABLE", 503]);
      await dw.validateToken("tok");
      assert.strictEqual(calls, 2);
    });
  }

  it("treats a 2xx { valid: false } or { error } as a 401 rejection, not a success status", async () => {
    const revoked = await client(async () => Response.json({ error: "REVOKED" })).validateToken("t");
    assert.deepStrictEqual(revoked, { ok: false, error: "REVOKED", status: 401, message: "REVOKED" });
    const invalid = await client(async () => Response.json({ valid: false })).validateToken("t");
    assert.strictEqual(!invalid.ok && invalid.status, 401);
  });

  it("maps 5xx and network errors to 503 and never negatively caches them", async () => {
    let calls = 0;
    const dw = client(async () => (calls++, new Response("<html>bad gateway</html>", { status: 502 })));
    const r = await dw.validateToken("tok");
    assert.deepStrictEqual([!r.ok && r.error, !r.ok && r.status], ["SERVICE_UNAVAILABLE", 503]);
    await dw.validateToken("tok");
    assert.strictEqual(calls, 2);

    let netCalls = 0;
    const down = client(async () => { netCalls++; throw new TypeError("ECONNREFUSED"); }, { maxRetries: 0 });
    const n = await down.validateToken("tok");
    assert.deepStrictEqual([!n.ok && n.error, !n.ok && n.status], ["NETWORK_ERROR", 503]);
    await down.validateToken("tok");
    assert.strictEqual(netCalls, 2);
  });

  it("still negatively caches a genuine 401 verdict", async () => {
    let calls = 0;
    const dw = client(async () => (calls++, Response.json({ valid: false, message: "bad token" }, { status: 401 })));
    await dw.validateToken("tok");
    await dw.validateToken("tok");
    assert.strictEqual(calls, 1);
  });

  it("hands every caller its own copy of a cached result", async () => {
    let calls = 0;
    const dw = client(async () => (calls++, Response.json({ valid: true, tenantId: "t1", rateLimit: { limit: 5, remaining: 4, reset: 1 } })));
    const [a, b] = await Promise.all([dw.validateToken("tok"), dw.validateToken("tok")]);
    assert.ok(a.ok && b.ok);
    assert.notStrictEqual(a, b);
    a.data.tenantId = "attacker";
    a.data.rateLimit.remaining = 999;
    const c = await dw.validateToken("tok");
    assert.ok(c.ok);
    assert.strictEqual(c.data.tenantId, "t1");
    assert.strictEqual(c.data.rateLimit.remaining, 4);
    assert.strictEqual(b.ok && b.data.tenantId, "t1");
    assert.strictEqual(calls, 1);
  });
});

describe("Redirects", () => {
  it("never follows a redirect from Daywalker Auth with credentials (real HTTP)", async () => {
    const stolen: string[] = [];
    const attacker = http.createServer((req, res) => { stolen.push(String(req.url)); res.end('{"valid":true}'); }).listen(0);
    const attackerPort = (attacker.address() as AddressInfo).port;
    const auth = http.createServer((_req, res) => { res.writeHead(307, { location: `http://localhost:${attackerPort}/steal` }); res.end(); }).listen(0);
    try {
      const key = await generateSigningKey();
      const dw = new Daywalker({ env, apiKey: "srv_live_secretsecret", serviceSlug: "svc", signingKey: key, authUrl: `http://127.0.0.1:${(auth.address() as AddressInfo).port}` });
      const r = await dw.validateToken("user-bearer-token-XYZ");
      assert.strictEqual(r.ok, false);
      assert.match(!r.ok ? r.message : "", /redirect/);
      await assert.rejects(dw.fetch("/api/v1/x"), (e: any) => e.code === "UNEXPECTED_REDIRECT");
      await assert.rejects(dw.fetchJwks(), /redirect/);
      assert.deepStrictEqual(stolen, []);
    } finally {
      attacker.close();
      auth.close();
    }
  });

  it("asks fetch not to follow redirects, and fetchJwks uses the configured fetch", async () => {
    const seen: RequestInit[] = [];
    const dw = client(async (_u, init) => (seen.push(init), Response.json({ keys: [] })));
    await dw.fetch("/x");
    await dw.fetchJwks();
    assert.deepStrictEqual(seen.map((i) => i.redirect), ["manual", "manual"]);
    assert.strictEqual(new Headers(seen[1].headers).has("authorization"), false);
    await assert.rejects(client(async () => Response.json({ nope: 1 })).fetchJwks(), /not a JWK Set/);
  });
});

describe("Signature components", () => {
  it('keeps "@path" path-only and signs the query as "@query" (RFC 9421 §2.2.6-2.2.7)', async () => {
    assert.strictEqual(normalizePath("/api/items?limit=10"), "/api/items");
    assert.deepStrictEqual(splitRequestTarget("//a/../b?x=//y#frag"), { path: "/b", query: "?x=//y" });
    assert.deepStrictEqual(splitRequestTarget("/a"), { path: "/a", query: "?" });

    const key = await generateSigningKey();
    const h = await signRequest({ method: "GET", path: "/api/items?limit=10", authority: "a.example", key });
    assert.match(h["Signature-Input"], /^sig1=\("@method" "@path" "@query" "@authority"\);/);
    const verify = (path: string, headers: Record<string, string | undefined> = h) =>
      verifyRequestSignature({ method: "GET", path, authority: "a.example", headers, publicKey: key.publicJwk, replayCheck: false });
    assert.strictEqual((await verify("/api/items?limit=10")).valid, true);
    assert.strictEqual((await verify("/api/items?limit=10&admin=1")).valid, false);
    assert.strictEqual((await verify("/api/items")).valid, false);

    // A signature without "@query" is refused for a request that has a query string.
    const noQuery = await signRequest({ method: "GET", path: "/api/items", authority: "a.example", key });
    assert.match((await verify("/api/items?admin=1", noQuery)).error!, /@query/);
    assert.strictEqual((await verify("/api/items", noQuery)).valid, true);
  });

  it("signs the query string from fetch()", async () => {
    const key = await generateSigningKey();
    let captured: { url: string; headers: Headers; body: unknown } | undefined;
    const dw = client(async (url, init) => ((captured = { url, headers: new Headers(init.headers), body: init.body }), Response.json({})), { signingKey: key });
    await dw.fetch("/api/v1/transfer?amount=1&to=alice", { method: "POST", body: { x: 1 } });
    const headers = Object.fromEntries(captured!.headers);
    const verify = (path: string) =>
      verifyRequestSignature({ method: "POST", path, authority: "auth.daywalker.dev", headers, body: captured!.body as string, publicKey: key.publicJwk, replayCheck: false });
    assert.strictEqual((await verify("/api/v1/transfer?amount=1&to=alice")).valid, true);
    assert.strictEqual((await verify("/api/v1/transfer?amount=1000&to=mallory")).valid, false);
    assert.strictEqual((await verify("/api/v1/transfer")).valid, false);
  });

  it("builds the base from the declared component list and requires @method, @path and @authority", async () => {
    const base = createSignatureBase({ method: "get", path: "/p?q=1", authority: "A.example", signatureParams: '("@authority" "@query" "x-extra");created=1;keyid="k";alg="ed25519"', additionalComponents: { "X-Extra": "v" } });
    assert.strictEqual(base, '"@authority": a.example\n"@query": ?q=1\n"x-extra": v\n"@signature-params": ("@authority" "@query" "x-extra");created=1;keyid="k";alg="ed25519"');
    assert.throws(() => createSignatureBase({ method: "GET", path: "/", authority: "a", signatureParams: '("@target-uri");created=1' }), /Unsupported derived component/);

    const key = await generateSigningKey();
    const created = Math.floor(Date.now() / 1000);
    const params = `("@authority");created=${created};keyid="${key.publicJwk.kid}";alg="ed25519"`;
    const sig = new Uint8Array(await crypto.subtle.sign("Ed25519", key.privateKey, new TextEncoder().encode(createSignatureBase({ method: "GET", path: "/", authority: "a.example", signatureParams: params }))));
    const r = await verifyRequestSignature({
      method: "GET", path: "/anything", authority: "a.example", publicKey: key.publicJwk, replayCheck: false,
      headers: { "signature-input": `sig1=${params}`, signature: `sig1=:${Buffer.from(sig).toString("base64")}:` },
    });
    assert.match(r.error!, /does not cover @method/);
  });

  it("requires content-digest coverage for bodies and for POST / PUT / PATCH", async () => {
    const key = await generateSigningKey();
    const bodyless = await signRequest({ method: "POST", path: "/api/x", authority: "a.example", key });
    assert.match(bodyless["Signature-Input"], /"content-digest"/);

    const get = await signRequest({ method: "GET", path: "/api/x", authority: "a.example", key });
    for (const [method, body] of [["POST", '{"admin":true}'], ["GET", '{"admin":true}'], ["PUT", undefined]] as const) {
      const r = await verifyRequestSignature({ method, path: "/api/x", authority: "a.example", headers: get, body, publicKey: key.publicJwk, replayCheck: false });
      assert.match(r.error ?? "valid", /content-digest/, `${method} ${body}`);
    }
    const ok = await verifyRequestSignature({ method: "POST", path: "/api/x", authority: "a.example", headers: bodyless, body: "", publicKey: key.publicJwk, replayCheck: false });
    assert.strictEqual(ok.valid, true);
  });

  it("rejects nonce, keyid and alg values that would inject Signature-Input parameters", async () => {
    const key = await generateSigningKey();
    const base = { method: "GET", path: "/", authority: "a.example", key };
    await assert.rejects(signRequest({ ...base, nonce: 'x";keyid="evil' }), /Invalid nonce/);
    await assert.rejects(signRequest({ ...base, nonce: "a b" }), /Invalid nonce/);
    await assert.rejects(signRequest({ ...base, keyid: 'k";created=1' }), /Invalid keyid/);
    await assert.rejects(signRequest({ ...base, keyid: "" }), /Invalid keyid/);
    await assert.rejects(signRequest({ ...base, alg: 'ed25519";nonce="x' }), /Invalid alg/);
    assert.match((await signRequest({ ...base, nonce: "dGVzdC1ub25jZQ" }))["Signature-Input"], /;nonce="dGVzdC1ub25jZQ"$/);
  });

  it("rejects malformed or duplicated Signature-Input parameters", async () => {
    const key = await generateSigningKey();
    const h = await signRequest({ method: "GET", path: "/", authority: "a.example", key });
    const verify = (input: string) =>
      verifyRequestSignature({ method: "GET", path: "/", authority: "a.example", headers: { ...h, "Signature-Input": input }, publicKey: key.publicJwk, replayCheck: false });
    assert.match((await verify(`${h["Signature-Input"]};created=1`)).error!, /Duplicate/);
    assert.match((await verify(`${h["Signature-Input"]};junk`)).error!, /Malformed/);
    assert.match((await verify(h["Signature-Input"].replace('"@path"', '"@path";req'))).error!, /Unsupported covered component/);
  });
});

describe("Replay store", () => {
  it("fails closed when the replay cache is full instead of forgetting unexpired signatures", async () => {
    const key = await generateSigningKey();
    const store = new SignatureReplayCache(1);
    const sign = () => signRequest({ method: "GET", path: "/", authority: "a.example", key, nonce: crypto.randomUUID() });
    const verify = (headers: Record<string, string | undefined>) =>
      verifyRequestSignature({ method: "GET", path: "/", authority: "a.example", headers, publicKey: key.publicJwk, replayStore: store });
    const first = await sign();
    assert.strictEqual((await verify(first)).valid, true);
    assert.match((await verify(await sign())).error!, /Replay cache is full/);
    assert.match((await verify(first)).error!, /Replay detected/);
  });

  it("uses a pluggable (async) replayStore", async () => {
    const key = await generateSigningKey();
    const seen = new Set<string>();
    const store: ReplayStore = {
      has: async (k) => seen.has(k),
      record: async (k) => (seen.has(k) ? false : (seen.add(k), true)),
    };
    const h = await signRequest({ method: "GET", path: "/", authority: "a.example", key });
    const verify = () => verifyRequestSignature({ method: "GET", path: "/", authority: "a.example", headers: h, publicKey: key.publicJwk, replayStore: store });
    assert.strictEqual((await verify()).valid, true);
    assert.strictEqual(seen.size, 1);
    assert.match((await verify()).error!, /Replay detected/);
  });
});

describe("fetch() retries, aborts and timeouts", () => {
  const fast = { initialDelayMs: 1, jitter: false };

  it("does not retry non-idempotent requests after a network error unless opted in", async () => {
    let calls = 0;
    const flaky: MockFetch = async () => { calls++; if (calls === 1) throw new TypeError("socket hang up"); return new Response("{}", { status: 201 }); };
    await assert.rejects(client(flaky).fetch("/api/v1/payments", { method: "POST", body: { amount: 5 }, retry: fast }), /socket hang up/);
    assert.strictEqual(calls, 1);

    calls = 0;
    assert.strictEqual((await client(flaky).fetch("/api/v1/items", { retry: fast })).status, 201);
    assert.strictEqual(calls, 2);

    calls = 0;
    const keys: (string | null)[] = [];
    const keyed: MockFetch = async (u, init) => (keys.push(new Headers(init.headers).get("idempotency-key")), flaky(u, init));
    assert.strictEqual((await client(keyed).fetch("/api/v1/payments", { method: "POST", body: {}, idempotencyKey: "pay-1", retry: fast })).status, 201);
    assert.deepStrictEqual(keys, ["pay-1", "pay-1"]);

    calls = 0;
    await client(flaky).fetch("/api/v1/payments", { method: "POST", body: {}, retry: { ...fast, retryNetworkErrors: true } });
    assert.strictEqual(calls, 2);
  });

  it("never sends or retries with an already-aborted signal", async () => {
    let calls = 0;
    const ac = new AbortController();
    ac.abort();
    const t = Date.now();
    await assert.rejects(client(async () => (calls++, new Response("{}"))).fetch("/x", { signal: ac.signal }), { name: "AbortError" });
    assert.strictEqual(calls, 0);
    assert.ok(Date.now() - t < 200);
  });

  it("aborts during backoff and does not retry an aborted request", async () => {
    let calls = 0;
    const ac = new AbortController();
    const dw = client(async (_u, init) => {
      calls++;
      if (init.signal?.aborted) throw init.signal.reason;
      return new Response("{}", { status: 429, headers: { "retry-after": "30" } });
    });
    const t = Date.now();
    setTimeout(() => ac.abort(), 30);
    await assert.rejects(dw.fetch("/x", { signal: ac.signal }), { name: "AbortError" });
    assert.strictEqual(calls, 1);
    assert.ok(Date.now() - t < 1000);
  });

  it("times out each attempt (default 5s, configurable) combined with the caller's signal", async () => {
    assert.strictEqual(new Daywalker({ env }).config.timeoutMs, 5000);
    const hang: MockFetch = (_u, init) =>
      new Promise((_r, reject) => init.signal!.addEventListener("abort", () => reject(init.signal!.reason)));
    let calls = 0;
    const counting: MockFetch = (u, init) => (calls++, hang(u, init));
    const t = Date.now();
    await assert.rejects(client(counting, { timeoutMs: 30 }).fetch("/x", { method: "POST", body: {} }), { name: "TimeoutError" });
    assert.strictEqual(calls, 1); // POST: a timeout is not retried
    assert.ok(Date.now() - t < 1000);

    calls = 0;
    await assert.rejects(client(counting, { timeoutMs: 1000 }).fetch("/x", { timeoutMs: 20, retry: { ...fast, maxRetries: 2 } }), { name: "TimeoutError" });
    assert.strictEqual(calls, 3); // GET: retried

    const r = await client(hang, { timeoutMs: 20, maxRetries: 0 }).validateToken("tok");
    assert.deepStrictEqual([!r.ok && r.error, !r.ok && r.status], ["NETWORK_ERROR", 503]);
    assert.match(!r.ok ? r.message : "", /timed out/);

    // Headers arrive but the body never finishes.
    const trickle: MockFetch = async () => new Response(new ReadableStream({ start: (c) => c.enqueue(new TextEncoder().encode('{"valid":')) }), { status: 200 });
    const slow = await client(trickle, { timeoutMs: 30 }).validateToken("tok");
    assert.deepStrictEqual([!slow.ok && slow.error, !slow.ok && slow.status], ["NETWORK_ERROR", 503]);
  });

  it("honors Retry-After beyond maxDelayMs, up to maxRetryAfterMs", async () => {
    const times: number[] = [];
    const dw = client(async () => (times.push(Date.now()), times.length === 1 ? new Response("{}", { status: 429, headers: { "retry-after": "1" } }) : Response.json({})));
    await dw.fetch("/x", { retry: { maxDelayMs: 10 } });
    assert.ok(times[1] - times[0] >= 990, `waited ${times[1] - times[0]}ms`);

    let calls = 0;
    const res = await client(async () => (calls++, new Response("{}", { status: 429, headers: { "retry-after": "3600" } }))).fetch("/x");
    assert.strictEqual(res.status, 429);
    assert.strictEqual(calls, 1);
  });

  it("applies config.retry beneath init.retry", async () => {
    let calls = 0;
    const limited: MockFetch = async () => (calls++, new Response("{}", { status: 429 }));
    const dw = client(limited, { retry: { maxRetries: 1, initialDelayMs: 1, jitter: false } });
    const t = Date.now();
    await dw.fetch("/x");
    assert.strictEqual(calls, 2);
    assert.ok(Date.now() - t < 300);
    calls = 0;
    await dw.fetch("/x", { retry: { maxRetries: 2 } });
    assert.strictEqual(calls, 3);
  });
});

describe("fetch() bodies and headers", () => {
  const capture = () => {
    const seen: { body: unknown; headers: Headers }[] = [];
    const fetch: MockFetch = async (_u, init) => (seen.push({ body: init.body, headers: new Headers(init.headers) }), Response.json({}));
    return { seen, fetch };
  };

  it("sends BodyInit bodies as-is instead of replacing them with JSON", async () => {
    const { seen, fetch } = capture();
    const dw = client(fetch);
    await dw.fetch("/form", { method: "POST", body: new URLSearchParams({ a: "1" }) });
    assert.strictEqual(seen[0].body, "a=1");
    assert.strictEqual(seen[0].headers.get("content-type"), "application/x-www-form-urlencoded;charset=UTF-8");
    const blob = new Blob(["hello"]);
    await dw.fetch("/blob", { method: "POST", body: blob });
    assert.strictEqual(seen[1].body, blob);
    const fd = new FormData();
    fd.set("f", "v");
    await dw.fetch("/fd", { method: "POST", body: fd });
    assert.strictEqual(seen[2].body, fd);
    assert.strictEqual(seen[2].headers.has("content-type"), false);
    await dw.fetch("/json", { method: "POST", body: [1, 2] });
    assert.strictEqual(seen[3].body, "[1,2]");
    assert.strictEqual(seen[3].headers.get("content-type"), "application/json");
    await assert.rejects(dw.fetch("/x", { method: "POST", body: new Date() }), /Unsupported fetch\(\) body/);
  });

  it("digests the exact bytes sent when signing, and refuses bodies it can't digest", async () => {
    const key = await generateSigningKey();
    const { seen, fetch } = capture();
    const dw = client(fetch, { signingKey: key });
    const verify = (i: number) =>
      verifyRequestSignature({ method: "POST", path: "/x", authority: "auth.daywalker.dev", headers: seen[i].headers, body: seen[i].body as Uint8Array | string, publicKey: key.publicJwk, replayCheck: false });
    const bytes = new Uint8Array([0, 255, 1, 2]);
    await dw.fetch("/x", { method: "POST", body: bytes });
    await dw.fetch("/x", { method: "POST", body: bytes.buffer });
    await dw.fetch("/x", { method: "POST", body: new Blob(["blob-bytes"], { type: "text/plain" }) });
    await dw.fetch("/x", { method: "POST", body: new URLSearchParams({ q: "a b" }) });
    for (let i = 0; i < 4; i++) assert.strictEqual((await verify(i)).valid, true, `body ${i}`);
    assert.deepStrictEqual([...(seen[1].body as Uint8Array)], [0, 255, 1, 2]);
    assert.strictEqual(seen[2].headers.get("content-type"), "text/plain");

    await assert.rejects(dw.fetch("/x", { method: "POST", body: new FormData() }), /FormData bodies can't be signed/);
    await assert.rejects(dw.fetch("/x", { method: "POST", body: new ReadableStream() }), /ReadableStream bodies can't be signed/);
  });

  it("does not overwrite an explicit Authorization header when signing", async () => {
    const key = await generateSigningKey();
    const { seen, fetch } = capture();
    const dw = client(fetch, { signingKey: key });
    await dw.fetch("/x", { headers: { Authorization: "Bearer caller-token" } });
    await dw.fetch("/x");
    assert.strictEqual(seen[0].headers.get("authorization"), "Bearer caller-token");
    assert.strictEqual(seen[1].headers.get("authorization"), "Bearer srv_live_service_key");
    assert.ok(seen[0].headers.has("signature"));
  });
});

describe("Keys, rotation and JWT strictness", () => {
  const mkKey = () => {
    const { privateKey } = crypto.generateKeyPairSync("ed25519");
    return { privateKey, jwk: crypto.createPublicKey(privateKey).export({ format: "jwk" }) as any };
  };
  const a = mkKey();
  const b = mkKey();
  const jwks = { keys: [{ ...a.jwk, kid: "key-a" }, { ...b.jwk, kid: "key-b" }] };
  const now = Math.floor(Date.now() / 1000);
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const jwt = (key: crypto.KeyObject, header: Record<string, unknown>, payload: Record<string, unknown> = { aud: "svc", exp: now + 600 }) => {
    const h = enc({ alg: "EdDSA", typ: "JWT", ...header });
    const p = enc({ jti: "j1", iss: "https://auth.daywalker.dev", ...payload });
    return `${h}.${p}.${crypto.sign(null, Buffer.from(`${h}.${p}`), key).toString("base64url")}`;
  };
  const verify = (token: string, publicKey: unknown = jwks) =>
    verifyJwtLease({ token, publicKey: publicKey as any, expectedServiceSlug: "svc", currentTime: now });

  it("selects the JWKS key by kid so rotation works", async () => {
    assert.strictEqual((await verify(jwt(b.privateKey, { kid: "key-b" }))).valid, true);
    assert.strictEqual((await verify(jwt(a.privateKey, { kid: "key-a" }), JSON.stringify(jwks))).valid, true);
    assert.match((await verify(jwt(b.privateKey, { kid: "key-a" }))).error!, /signature verification failed/);
    assert.match((await verify(jwt(b.privateKey, {}))).error!, /several keys/);
    assert.match((await verify(jwt(b.privateKey, { kid: "nope" }))).error!, /No key in JWKS matches/);
    // A single-key JWKS is used whatever the kid says (the signature still has to verify).
    assert.strictEqual((await verify(jwt(a.privateKey, { kid: "other" }), { keys: [a.jwk] })).valid, true);
    assert.strictEqual((await loadPublicKey(JSON.stringify(jwks), "key-b")).publicJwk.x, b.jwk.x);

    const client = new Daywalker({ env, serviceSlug: "svc", daywalkerPublicKey: JSON.stringify(jwks), fetch: async () => Response.json({}) });
    assert.strictEqual((await client.validateToken({ token: jwt(b.privateKey, { kid: "key-b" }), offlineOnly: true })).ok, true);
  });

  it("rejects a crit header and non-canonical base64url segments", async () => {
    assert.match((await verify(jwt(a.privateKey, { kid: "key-a", crit: ["exp"] }))).error!, /crit/);
    const good = jwt(a.privateKey, { kid: "key-a" });
    assert.strictEqual((await verify(good)).valid, true);
    const [h, p, s] = good.split(".");
    const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    const idx = alphabet.indexOf(s[s.length - 1]);
    const sameBytes = s.slice(0, -1) + alphabet[(idx & ~3) | ((idx + 1) & 3)]; // differs only in unused low bits
    for (const variant of [`${h}.${p}.${sameBytes}`, `${h}.${p}.${s}==`, `${h}.${p}.${s}!!`, `${h}.${p} .${s}`, `${h}=.${p}.${s}`]) {
      assert.strictEqual((await verify(variant)).valid, false, variant.slice(-6));
    }
    assert.throws(() => base64UrlToBytesStrict("ab+/"), /Invalid/);
    assert.throws(() => base64UrlToBytesStrict("QR"), /Non-canonical/);
    assert.deepStrictEqual([...base64UrlToBytesStrict("QQ")], [65]);
  });

  it("publishes the previous signing key next to the current one during rotation", async () => {
    const current = await generateSigningKey();
    const previous = await generateSigningKey();
    const dw = new Daywalker({ env, signingKey: current, previousSigningKey: previous.privateKeyPkcs8Base64 });
    assert.deepStrictEqual((await dw.keys()).keys.map((k) => k.kid), [current.publicJwk.kid, previous.publicJwk.kid]);
    const fromEnv = new Daywalker({ env: { DAYWALKER_SIGNING_KEY: current.privateKeyPkcs8Base64, DAYWALKER_SIGNING_KEY_PREVIOUS: previous.privateKeyPkcs8Base64 } });
    assert.strictEqual((await fromEnv.keys()).keys.length, 2);
    const broken = new Daywalker({ env, signingKey: current, previousSigningKey: "not-a-key" });
    assert.deepStrictEqual((await broken.keys()).keys.map((k) => k.kid), [current.publicJwk.kid]);
    assert.ok((await broken.selfCheck()).problems.some((p) => /Previous signing key/.test(p)));
  });
});
