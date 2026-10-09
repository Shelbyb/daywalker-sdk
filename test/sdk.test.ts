import { describe, it } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import util from "node:util";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import {
  computeContentDigest,
  createSignatureBase,
  createDaywalker,
  daywalker,
  Daywalker,
  DaywalkerAuthError,
  DaywalkerRateLimitError,
  generateSigningKey,
  loadSigningKey,
  publicHostname,
  registerPublicKey,
  resolveConfig,
  signRequest,
  verifyJwtLease,
  verifyRequestSignature,
  calculateJwkThumbprint,
  SIGNATURE_ALG,
  SIGNATURE_LABEL,
} from "../src/index.js";
import { withDaywalkerAuth, createDaywalkerMiddleware } from "../src/next.js";
import { daywalkerAuth, daywalkerMiddleware } from "../src/middleware.js";

const vectors = JSON.parse(
  fs.readFileSync(new URL("../test-vectors/signing-rfc9421.json", import.meta.url), "utf8")
);

describe("RFC 9421 / RFC 9530 WebCrypto signing protocol", () => {
  it("derives the RFC 7638 JWK thumbprint and public JWK", async () => {
    const key = await loadSigningKey(vectors.privateKeyPkcs8Base64);
    assert.strictEqual(key.publicJwk.kty, "OKP");
    assert.strictEqual(key.publicJwk.crv, "Ed25519");
    assert.strictEqual(key.publicJwk.x, vectors.publicJwk.x);
    assert.strictEqual(key.publicJwk.kid, vectors.publicJwk.kid);
    assert.strictEqual(await calculateJwkThumbprint(key.publicJwk), vectors.publicJwk.kid);
  });

  for (const v of vectors.cases) {
    it(`computes and verifies "${v.name}" signature correctly`, async () => {
      const key = await loadSigningKey(vectors.privateKeyPkcs8Base64);
      const digest = await computeContentDigest(v.body);
      assert.strictEqual(digest, v.contentDigest);

      const base = createSignatureBase({
        method: v.method,
        path: v.path,
        authority: v.authority,
        contentDigest: digest,
        signatureParams: v.signatureParams,
      });
      assert.strictEqual(base, v.signatureBase);

      const headers = await signRequest({
        method: v.method,
        path: v.path,
        authority: v.authority,
        body: v.body,
        key,
        created: v.timestamp,
        apiKey: "srv_live_test_token",
      });

      assert.strictEqual(headers["Content-Digest"], v.contentDigest);
      assert.strictEqual(headers["Signature-Input"], `${SIGNATURE_LABEL}=${v.signatureParams}`);
      assert.match(headers["Signature"], new RegExp(`^${SIGNATURE_LABEL}=:[A-Za-z0-9+/=_-]+:$`));
      assert.strictEqual(headers["Authorization"], "Bearer srv_live_test_token");

      // Verify signature with public JWK
      const verifyRes = await verifyRequestSignature({
        method: v.method,
        path: v.path,
        authority: v.authority,
        headers,
        body: v.body,
        publicKey: key.publicJwk,
        currentTime: v.timestamp,
        replayCheck: false,
      });
      assert.strictEqual(verifyRes.valid, true);
      assert.strictEqual(verifyRes.keyid, vectors.publicJwk.kid);
    });
  }

  it("rejects tampered body or expired timestamp in verification", async () => {
    const key = await loadSigningKey(vectors.privateKeyPkcs8Base64);
    const v = vectors.cases[0];
    const headers = await signRequest({
      method: v.method,
      path: v.path,
      authority: v.authority,
      body: v.body,
      key,
      created: v.timestamp,
    });

    // Tampered body
    const tampered = await verifyRequestSignature({
      method: v.method,
      path: v.path,
      authority: v.authority,
      headers,
      body: '{"tampered": true}',
      publicKey: key.publicJwk,
      currentTime: v.timestamp,
      replayCheck: false,
    });
    assert.strictEqual(tampered.valid, false);
    assert.match(tampered.error!, /Content-Digest/);

    // Expired timestamp
    const expired = await verifyRequestSignature({
      method: v.method,
      path: v.path,
      authority: v.authority,
      headers,
      body: v.body,
      publicKey: key.publicJwk,
      currentTime: v.timestamp + 500, // beyond 300s
      replayCheck: false,
    });
    assert.strictEqual(expired.valid, false);
    assert.match(expired.error!, /expired/i);

    // Replay detection check
    const firstVerify = await verifyRequestSignature({
      method: v.method,
      path: v.path,
      authority: v.authority,
      headers,
      body: v.body,
      publicKey: key.publicJwk,
      currentTime: v.timestamp,
      replayCheck: true,
    });
    assert.strictEqual(firstVerify.valid, true);

    const replayVerify = await verifyRequestSignature({
      method: v.method,
      path: v.path,
      authority: v.authority,
      headers,
      body: v.body,
      publicKey: key.publicJwk,
      currentTime: v.timestamp,
      replayCheck: true,
    });
    assert.strictEqual(replayVerify.valid, false);
    assert.match(replayVerify.error || "", /Replay detected/);
  });
});

describe("Public key direct registration (Push Architecture)", () => {
  it("registers public key with Daywalker Auth", async () => {
    const key = await generateSigningKey();
    let sentPayload: any = null;
    let authHeader: string | null = null;

    const mockFetch = async (_url: string | URL | Request, init?: RequestInit) => {
      authHeader = new Headers(init?.headers).get("authorization");
      sentPayload = JSON.parse(String(init?.body));
      return Response.json({ ok: true, keyId: key.publicJwk.kid });
    };

    const res = await registerPublicKey({
      apiKey: "srv_live_reg_token",
      serviceSlug: "testservice",
      domain: "testservice.daywalker.dev",
      publicJwk: key.publicJwk,
      fetchFn: mockFetch as any,
    });

    assert.strictEqual(res.ok, true);
    assert.strictEqual(authHeader, "Bearer srv_live_reg_token");
    assert.strictEqual(sentPayload.serviceSlug, "testservice");
    assert.strictEqual(sentPayload.keyId, key.publicJwk.kid);
    assert.strictEqual(sentPayload.publicKey.x, key.publicJwk.x);
  });
});

describe("Zero-egress offline JWT lease verification", () => {
  const { privateKey } = crypto.generateKeyPairSync("ed25519");
  const pubJwk = crypto.createPublicKey(privateKey).export({ format: "jwk" }) as any;

  function createTestJwt(payload: Record<string, unknown>) {
    const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
    const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const sig = crypto.sign(null, Buffer.from(`${header}.${body}`, "utf8"), privateKey).toString("base64url");
    return `${header}.${body}.${sig}`;
  }

  it("verifies a valid asymmetric JWT lease locally without network egress", async () => {
    const now = Math.floor(Date.now() / 1000);
    const jwt = createTestJwt({
      sub: "tok_12345",
      serviceSlug: "myservice",
      userId: "usr_abc",
      exp: now + 3600,
      nbf: now - 10,
      rateLimit: { limit: 120, remaining: 119, reset: now + 60 },
    });

    const res = await verifyJwtLease({
      token: jwt,
      publicKey: pubJwk,
      expectedServiceSlug: "myservice",
      currentTime: now,
    });

    assert.strictEqual(res.valid, true);
    assert.strictEqual(res.payload?.sub, "tok_12345");
    assert.strictEqual(res.payload?.userId, "usr_abc");
  });

  it("rejects expired or mismatched service JWT lease", async () => {
    const now = Math.floor(Date.now() / 1000);
    const expiredJwt = createTestJwt({
      sub: "tok_12345",
      serviceSlug: "myservice",
      exp: now - 10,
    });

    const res1 = await verifyJwtLease({ token: expiredJwt, publicKey: pubJwk, currentTime: now });
    assert.strictEqual(res1.valid, false);
    assert.match(res1.error!, /expired/i);

    const validJwt = createTestJwt({
      sub: "tok_12345",
      serviceSlug: "other-service",
      exp: now + 3600,
    });
    const res2 = await verifyJwtLease({
      token: validJwt,
      publicKey: pubJwk,
      expectedServiceSlug: "myservice",
      currentTime: now,
    });
    assert.strictEqual(res2.valid, false);
    assert.match(res2.error!, /mismatch/i);
  });
});

describe("Daywalker Client class & lazy proxy", () => {
  it("supports instantiation and lazy proxy", async () => {
    const client = new Daywalker({
      apiKey: "srv_live_inst",
      serviceSlug: "myservice",
    });
    assert.strictEqual(client.config.apiKey, "srv_live_inst");
    assert.strictEqual(client.config.serviceSlug, "myservice");

    // Lazy default instance proxy
    assert.ok(typeof daywalker.fetch === "function");
    assert.ok(typeof daywalker.validateToken === "function");
    assert.ok(typeof daywalker.requireValidToken === "function");
    assert.ok(typeof daywalker === "function");
  });

  it("performs signed fetch and discriminated union validation", async () => {
    const key = await generateSigningKey();
    let capturedHeaders: Headers | null = null;

    const client = new Daywalker({
      apiKey: "srv_live_test",
      serviceSlug: "sonalyze",
      signingKey: key.privateKeyPkcs8Base64,
      fetch: async (url, init) => {
        capturedHeaders = new Headers(init?.headers);
        return Response.json({
          valid: true,
          serviceSlug: "sonalyze",
          tenantId: "ten_123",
          rateLimit: { limit: 100, remaining: 99, reset: 123456 },
        });
      },
    });

    const result = await client.validateToken();
    assert.strictEqual(result.ok, true);
    if (result.ok) {
      assert.strictEqual(result.data.serviceSlug, "sonalyze");
      assert.strictEqual(result.data.tenantId, "ten_123");
      assert.strictEqual(result.data.rateLimit.remaining, 99);
    }

    assert.ok(capturedHeaders!.has("signature-input"));
    assert.ok(capturedHeaders!.has("signature"));
    assert.strictEqual(capturedHeaders!.get("authorization"), "Bearer srv_live_test");

    const payload = await client.requireValidToken();
    assert.strictEqual(payload.tenantId, "ten_123");
  });

  it("handles automatic retries on 429 rate limits", async () => {
    let attempts = 0;
    const client = new Daywalker({
      apiKey: "srv_live_test",
      serviceSlug: "sonalyze",
      maxRetries: 3,
      retry: { initialDelayMs: 10, maxDelayMs: 50 },
      fetch: async () => {
        attempts++;
        if (attempts < 3) {
          return new Response(JSON.stringify({ error: "RATE_LIMITED", message: "chill" }), {
            status: 429,
            headers: { "Content-Type": "application/json", "Retry-After": "0" },
          });
        }
        return Response.json({ ok: true });
      },
    });

    const res = await client.fetch("/api/v1/test");
    assert.strictEqual(res.status, 200);
    assert.strictEqual(attempts, 3);
  });

  it("returns discriminated error on validation failures and throws typed errors", async () => {
    const client = new Daywalker({
      apiKey: "srv_invalid",
      serviceSlug: "sonalyze",
      fetch: async () => {
        return new Response(JSON.stringify({ error: "EXPIRED", message: "Token expired" }), {
          status: 401,
          headers: { "Content-Type": "application/json" },
        });
      },
    });

    const result = await client.validateToken();
    assert.strictEqual(result.ok, false);
    if (!result.ok) {
      assert.strictEqual(result.error, "EXPIRED");
      assert.strictEqual(result.status, 401);
      assert.strictEqual(result.message, "Token expired");
    }

    await assert.rejects(client.requireValidToken(), (err: unknown) => {
      assert.ok(err instanceof DaywalkerAuthError);
      assert.strictEqual((err as DaywalkerAuthError).code, "EXPIRED");
      assert.strictEqual((err as DaywalkerAuthError).status, 401);
      return true;
    });
  });
});

describe("Framework Middleware Adapters", () => {
  it("withDaywalkerAuth wraps Next.js App Router handlers", async () => {
    const client = new Daywalker({
      serviceSlug: "myservice",
      fetch: async () => Response.json({ valid: true, tenantId: "ten_next", serviceSlug: "myservice" }),
    });

    const handler = withDaywalkerAuth(async (req, { auth }) => {
      return Response.json({ hello: auth.tenantId });
    }, client);

    // Test missing auth header
    const badReq = new Request("https://localhost/api/test");
    const badRes = await handler(badReq);
    assert.strictEqual(badRes.status, 401);

    // Test valid auth
    const goodReq = new Request("https://localhost/api/test", {
      headers: { authorization: "Bearer srv_valid_token" },
    });
    const goodRes = await handler(goodReq);
    assert.strictEqual(goodRes.status, 200);
    const data = await goodRes.json();
    assert.strictEqual(data.hello, "ten_next");
  });

  it("createDaywalkerMiddleware applies hardened security rules in Next.js", async () => {
    const client = new Daywalker({
      apiKey: "srv_live_key",
      serviceSlug: "sonalyze",
      fetch: async () => Response.json({ valid: true, tenantId: "ten_live", serviceSlug: "sonalyze" }),
    });

    const mw = createDaywalkerMiddleware({ client });

    // 0. Blocks malformed Server Action probes (CVE-2025-55182 mitigation)
    const probeReq = new Request("https://localhost/dashboard", {
      headers: { "next-action": "invalid_probe_id_not_hex" },
    });
    const probeRes = await mw(probeReq);
    assert.strictEqual(probeRes.status, 400);

    // 1. Passes health check probes without auth check
    const healthReq = new Request("https://localhost/healthz");
    const healthRes = await mw(healthReq);
    assert.strictEqual(healthRes.headers.get("x-middleware-next"), "1");

    // 2. Protects normal pages when token valid
    const normalReq = new Request("https://localhost/dashboard");
    const normalRes = await mw(normalReq);
    assert.strictEqual(normalRes.headers.get("x-middleware-next"), "1");

    // 3. Handles invalid token on API routes (returns JSON 401 with CORS)
    const invalidClient = new Daywalker({
      apiKey: "srv_bad",
      serviceSlug: "sonalyze",
      fetch: async () => new Response(JSON.stringify({ error: "REVOKED", message: "Token revoked" }), { status: 401 }),
    });
    const invalidMw = createDaywalkerMiddleware({ client: invalidClient });

    const apiReq = new Request("https://localhost/api/data");
    const apiRes = await invalidMw(apiReq);
    assert.strictEqual(apiRes.status, 401);
    assert.strictEqual(apiRes.headers.get("access-control-allow-origin"), "*");

    // 4. Handles invalid token on UI page (redirects to /service-error)
    const uiReq = new Request("https://localhost/dashboard?tab=security");
    const uiRes = await invalidMw(uiReq);
    assert.strictEqual(uiRes.status, 307);
    const loc = uiRes.headers.get("location") || "";
    assert.ok(loc.includes("/service-error"));
    assert.ok(loc.includes("from=%2Fdashboard%3Ftab%3Dsecurity"));

    // 5. Blocks open redirect malicious target
    const evilReq = new Request("https://localhost//evil.com/hack");
    const evilRes = await invalidMw(evilReq);
    const evilLoc = evilRes.headers.get("location") || "";
    assert.strictEqual(evilLoc.includes("evil.com"), false);
  });

  it("daywalkerAuth works as Web / Hono middleware", async () => {
    const client = new Daywalker({
      serviceSlug: "myservice",
      fetch: async () => Response.json({ valid: true, tenantId: "ten_hono", serviceSlug: "myservice" }),
    });

    const mw = daywalkerAuth({ client });

    const context: any = {
      req: {
        header: (name: string) => (name === "authorization" ? "Bearer srv_hono_token" : undefined),
      },
      set: (key: string, val: any) => {
        context[key] = val;
      },
    };

    let nextCalled = false;
    await mw(context, async () => {
      nextCalled = true;
    });

    assert.strictEqual(nextCalled, true);
    assert.strictEqual(context.auth?.tenantId, "ten_hono");
  });

  it("masks secrets in JSON serialization and inspect", () => {
    const client = new Daywalker({
      apiKey: "srv_live_1234567890abcdef",
      serviceSlug: "masked-svc",
      signingKey: "MC4CAQAwBQYDK2VwBCIEIPm4rJ4eQyM",
    });

    const json = JSON.stringify(client);
    assert.strictEqual(json.includes("srv_live_1234567890abcdef"), false);
    assert.ok(json.includes("srv_...cdef"));

    const inspectStr = util.inspect(client);
    assert.strictEqual(inspectStr.includes("srv_live_1234567890abcdef"), false);
  });

  it("redacts secrets and bearer tokens from error messages and serialization", () => {
    const error = new DaywalkerAuthError("Failed validating Bearer srv_live_secret1234567890 with token eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakSignature");
    assert.strictEqual(error.message.includes("srv_live_secret1234567890"), false);
    assert.strictEqual(error.message.includes("doNotLeakSignature"), false);
    assert.ok(error.message.includes("Bearer [REDACTED]"));

    const errorJson = JSON.stringify(error);
    assert.strictEqual(errorJson.includes("srv_live_secret1234567890"), false);
    assert.strictEqual(errorJson.includes("doNotLeakSignature"), false);

    const errorInspect = util.inspect(error);
    assert.strictEqual(errorInspect.includes("srv_live_secret1234567890"), false);
  });
});

describe("Decoupled CLI", () => {
  it("outputs JSON with --json flag and does not inject route files", () => {
    const cli = path.resolve("dist/cli.js");
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-cli-"));
    const run = (...args: string[]) =>
      execFileSync(process.execPath, [cli, ...args], { cwd: dir, encoding: "utf8", stdio: "pipe" });

    try {
      const output = run("init", "--service", "json-svc", "--json", "--skip-register");
      const parsed = JSON.parse(output);
      assert.strictEqual(parsed.DAYWALKER_SERVICE_SLUG, "json-svc");
      assert.ok(parsed.DAYWALKER_KEY_ID);
      assert.ok(parsed.DAYWALKER_SIGNING_KEY);
      assert.strictEqual(parsed.DAYWALKER_AUTH_URL, "https://auth.daywalker.dev");

      // Verify no route files created
      assert.strictEqual(fs.existsSync(path.join(dir, "app/.well-known/daywalker-keys.json/route.ts")), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
