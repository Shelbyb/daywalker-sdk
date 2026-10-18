import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import {
  Daywalker,
  DaywalkerAuthError,
  generateSigningKey,
  leaseServices,
  parseServiceSlugs,
  registerPublicKey,
  resolveConfig,
  verifyJwtLease,
} from "../src/index.js";
import { withOAuth } from "./helpers/oauth.js";

const { privateKey } = crypto.generateKeyPairSync("ed25519");
const pubJwk = crypto.createPublicKey(privateKey).export({ format: "jwk" }) as any;
const now = () => Math.floor(Date.now() / 1000);

/** A lease shaped like the one Daywalker issues for a token that covers gigpulse and devpulse. */
function lease(overrides: Record<string, unknown> = {}) {
  const payload = {
    iss: "https://auth.daywalker.dev",
    sub: "tok_1",
    aud: ["gigpulse", "devpulse"],
    services: ["gigpulse", "devpulse"],
    service: "gigpulse",
    domain: "gigpulse.daywalker.dev",
    jti: "jti-1",
    exp: now() + 3600,
    ...overrides,
  };
  const header = Buffer.from(JSON.stringify({ alg: "EdDSA", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const sig = crypto.sign(null, Buffer.from(`${header}.${body}`, "utf8"), privateKey).toString("base64url");
  return `${header}.${body}.${sig}`;
}

describe("service slug lists", () => {
  it("parses comma/space separated slugs, de-duplicated and lower-cased", () => {
    assert.deepStrictEqual(parseServiceSlugs("GigPulse, devpulse  gigpulse,"), ["gigpulse", "devpulse"]);
    assert.deepStrictEqual(parseServiceSlugs(["a,b", "A"]), ["a", "b"]);
    assert.deepStrictEqual(parseServiceSlugs(undefined), []);
    assert.deepStrictEqual(parseServiceSlugs(""), []);
  });

  it("uses the first slug as the default and keeps the full list", () => {
    const c = resolveConfig({ env: { DAYWALKER_API_KEY: "k", DAYWALKER_SERVICE_SLUG: "gigpulse,devpulse" } });
    assert.strictEqual(c.serviceSlug, "gigpulse");
    assert.deepStrictEqual(c.serviceSlugs, ["gigpulse", "devpulse"]);
    assert.deepStrictEqual(c.problems, []);

    const single = resolveConfig({ serviceSlug: "Sonalyze", env: {} });
    assert.strictEqual(single.serviceSlug, "sonalyze");
    assert.deepStrictEqual(single.serviceSlugs, ["sonalyze"]);

    const arr = resolveConfig({ serviceSlugs: ["b", "a"], serviceSlug: "ignored", env: {} });
    assert.strictEqual(arr.serviceSlug, "b");

    const none = resolveConfig({ env: {} });
    assert.strictEqual(none.serviceSlug, null);
    assert.deepStrictEqual(none.serviceSlugs, []);
    // the slug is optional: requests never name a service
    assert.ok(!none.problems.some((p) => p.includes("DAYWALKER_SERVICE_SLUG")));
  });
});

describe("JWT lease listing several services", () => {
  it("verifies for each listed service and rejects others", async () => {
    const token = lease();
    for (const slug of ["gigpulse", "devpulse", "DevPulse"]) {
      const res = await verifyJwtLease({ token, publicKey: pubJwk, expectedServiceSlug: slug });
      assert.strictEqual(res.valid, true, `${slug}: ${res.error}`);
    }
    const other = await verifyJwtLease({ token, publicKey: pubJwk, expectedServiceSlug: "sonalyze" });
    assert.strictEqual(other.valid, false);
    assert.match(other.error!, /mismatch/i);
  });

  it("rejects a lease whose services claim leaves the service out even if aud lists it", async () => {
    const token = lease({ services: ["gigpulse"], aud: ["gigpulse", "devpulse"] });
    const res = await verifyJwtLease({ token, publicKey: pubJwk, expectedServiceSlug: "devpulse" });
    assert.strictEqual(res.valid, false);
    assert.match(res.error!, /services mismatch/i);

    const bad = lease({ services: "devpulse" });
    assert.strictEqual((await verifyJwtLease({ token: bad, publicKey: pubJwk, expectedServiceSlug: "devpulse" })).valid, false);
  });

  it("still verifies leases issued before multi-service tokens", async () => {
    const old = lease({ services: undefined, aud: undefined, service: undefined, serviceSlug: "gigpulse" });
    assert.strictEqual((await verifyJwtLease({ token: old, publicKey: pubJwk, expectedServiceSlug: "gigpulse" })).valid, true);
  });

  it("lists the services of any lease shape", () => {
    assert.deepStrictEqual(leaseServices({ services: ["A", "b", "a"] }), ["a", "b"]);
    assert.deepStrictEqual(leaseServices({ aud: ["x", "y"] }), ["x", "y"]);
    assert.deepStrictEqual(leaseServices({ aud: "x" }), ["x"]);
    assert.deepStrictEqual(leaseServices({ serviceSlug: "legacy" }), ["legacy"]);
    assert.deepStrictEqual(leaseServices({ service: "one" }), ["one"]);
    assert.deepStrictEqual(leaseServices({}), []);
  });

  it("validateToken reports every service on an offline-verified lease", async () => {
    const client = new Daywalker({ apiKey: "k", serviceSlug: "devpulse", daywalkerPublicKey: pubJwk });
    const res = await client.validateToken({ token: lease(), offlineOnly: true });
    assert.strictEqual(res.ok, true);
    if (res.ok) {
      assert.strictEqual(res.data.serviceSlug, "devpulse");
      assert.deepStrictEqual(res.data.services, ["gigpulse", "devpulse"]);
      assert.strictEqual(res.data.offlineVerified, true);
    }

    const wrong = new Daywalker({ apiKey: "k", serviceSlug: "sonalyze", daywalkerPublicKey: pubJwk });
    const rejected = await wrong.validateToken({ token: lease(), offlineOnly: true });
    assert.strictEqual(rejected.ok, false);
  });

  it("validates a lease for any configured service when several are configured", async () => {
    const client = new Daywalker({ apiKey: "k", serviceSlug: "gigpulse,devpulse", daywalkerPublicKey: pubJwk });
    const token = lease();
    assert.strictEqual((await client.validateToken({ token, offlineOnly: true })).ok, true);
    assert.strictEqual((await client.validateToken({ token, serviceSlug: "devpulse", offlineOnly: true })).ok, true);
  });
});

describe("online validation of a multi-service token", () => {
  it("surfaces the services list, and falls back to the validated slug from older servers", async () => {
    const answer = (extra: Record<string, unknown>) =>
      new Daywalker({
        apiKey: "k",
        serviceSlug: "devpulse",
        fetch: withOAuth(async () =>
          Response.json({ valid: true, serviceSlug: "devpulse", tenantId: "t", rateLimit: { limit: 1, remaining: 1, reset: 1 }, ...extra })),
      }).validateToken("srv_live_x");

    const multi = await answer({ services: ["gigpulse", "devpulse"] });
    assert.ok(multi.ok);
    if (multi.ok) assert.deepStrictEqual(multi.data.services, ["gigpulse", "devpulse"]);

    const legacy = await answer({});
    assert.ok(legacy.ok);
    if (legacy.ok) assert.deepStrictEqual(legacy.data.services, ["devpulse"]);

    const malformed = await answer({ services: "devpulse" });
    assert.strictEqual(malformed.ok, false);
  });
});

describe("client credentials tokens", () => {
  const tokenBody = (n: number, extra: Record<string, unknown> = {}) => ({
    access_token: `access-${n}`,
    refresh_token: `refresh-${n}`,
    token_type: "Bearer",
    expires_in: 900,
    expires_at: Math.floor(Date.now() / 1000) + 900,
    refresh_expires_in: 2592000,
    scope: "gigpulse devpulse",
    services: ["gigpulse", "devpulse"],
    ...extra,
  });

  const make = async (respond: (body: any, n: number) => Response, sent: any[] = []) =>
    new Daywalker({
      apiKey: "srv_live_k",
      signingKey: (await generateSigningKey()).privateKeyPkcs8Base64,
      fetch: async (_url, init) => {
        const body = JSON.parse(String(init?.body ?? "{}"));
        sent.push(body);
        return respond(body, sent.length);
      },
    });

  it("getTokens sends no service slug and returns every service", async () => {
    const sent: any[] = [];
    const client = await make((_b, n) => Response.json(tokenBody(n)), sent);
    const res = await client.getTokens();
    assert.deepStrictEqual(sent[0], { grant_type: "client_credentials" });
    assert.deepStrictEqual(res.services, ["gigpulse", "devpulse"]);
    assert.strictEqual(res.accessToken, "access-1");
    assert.strictEqual(res.refreshToken, "refresh-1");
  });

  it("narrows with scope and expiresIn, and refuses an empty scope locally", async () => {
    const sent: any[] = [];
    const client = await make((_b, n) => Response.json(tokenBody(n, { services: ["devpulse"] })), sent);
    await client.getTokens({ scope: ["DevPulse", "devpulse"], expiresIn: 600 });
    assert.deepStrictEqual(sent[0], { grant_type: "client_credentials", scope: "devpulse", expires_in: 600 });
    await assert.rejects(client.getTokens({ scope: [] }), (e: any) => e instanceof DaywalkerAuthError && e.status === 400);
  });

  it("surfaces server errors with their code", async () => {
    const client = await make(() => Response.json({ error: "invalid_scope", code: "SERVICE_NOT_GRANTED", message: "nope" }, { status: 403 }));
    await assert.rejects(client.getTokens({ scope: ["sonalyze"] }), (e: any) => e.status === 403 && e.code === "SERVICE_NOT_GRANTED");
    const broken = await make(() => Response.json({}, { status: 200 }));
    await assert.rejects(broken.getTokens(), DaywalkerAuthError);
  });

  it("refreshTokens rotates: sends the refresh token and stores the new pair", async () => {
    const sent: any[] = [];
    const client = await make((_b, n) => Response.json(tokenBody(n)), sent);
    await client.getTokens();
    const next = await client.refreshTokens();
    assert.deepStrictEqual(sent[1], { grant_type: "refresh_token", refresh_token: "refresh-1" });
    assert.strictEqual(next.refreshToken, "refresh-2");
    await client.refreshTokens();
    assert.strictEqual(sent[2].refresh_token, "refresh-2");
  });

  it("accessToken() reuses a fresh token, and refreshes once for concurrent callers when it is about to expire", async () => {
    const sent: any[] = [];
    const client = await make((_b, n) => Response.json(tokenBody(n, n === 1 ? { expires_at: Math.floor(Date.now() / 1000) + 5 } : {})), sent);
    assert.strictEqual(await client.accessToken(), "access-1");
    const [a, b] = await Promise.all([client.accessToken(), client.accessToken()]);
    assert.strictEqual(a, "access-2");
    assert.strictEqual(b, "access-2");
    assert.strictEqual(sent.length, 2);
    assert.strictEqual(await client.accessToken(), "access-2");
    assert.strictEqual(sent.length, 2);
  });

  it("accessToken() starts a new session when the refresh token was rejected", async () => {
    const sent: any[] = [];
    const client = await make((b, n) => {
      if (b.grant_type === "refresh_token") return Response.json({ error: "invalid_grant", message: "revoked" }, { status: 400 });
      return Response.json(tokenBody(n, n === 1 ? { expires_at: 1 } : {}));
    }, sent);
    await client.getTokens();
    assert.strictEqual(await client.accessToken(), "access-3");
    assert.deepStrictEqual(sent.map((s) => s.grant_type), ["client_credentials", "refresh_token", "client_credentials"]);
  });
});

describe("key registration names the service(s)", () => {
  it("sends serviceSlug (list) to Daywalker so it can refuse early", async () => {
    const key = await generateSigningKey();
    let sent: any;
    const res = await registerPublicKey({
      apiKey: "srv_live_k",
      serviceSlug: "gigpulse,devpulse",
      domain: "gigpulse.daywalker.dev",
      publicJwk: key.publicJwk,
      fetchFn: (async (_u: string, init: RequestInit) => {
        sent = JSON.parse(String(init.body));
        return Response.json({ error: "service_not_covered", message: "This API key doesn't cover service 'devpulse'" }, { status: 403 });
      }) as any,
    });
    assert.strictEqual(sent.serviceSlug, "gigpulse,devpulse");
    assert.strictEqual(res.ok, false);
    assert.strictEqual(res.status, 403);
    assert.match(res.error!, /doesn't cover/);
  });
});

describe("CLI init with several services", () => {
  const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
  const TSX = import.meta.resolve("tsx");
  let server: http.Server;
  let authUrl = "";
  const bodies: any[] = [];

  before(async () => {
    server = http.createServer((req, res) => {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        bodies.push(JSON.parse(body));
        res.writeHead(201, { "content-type": "application/json" });
        res.end("{}");
      });
    });
    await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
    authUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  after(() => server.close());

  const run = (cwd: string, args: string[], env: Record<string, string> = {}) =>
    new Promise<{ status: number | null; stdout: string; stderr: string }>((resolve, reject) => {
      const clean: Record<string, string> = {};
      for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("DAYWALKER_") && v !== undefined) clean[k] = v;
      const child = spawn(process.execPath, ["--import", TSX, CLI, ...args], { cwd, env: { ...clean, ...env } });
      let stdout = "";
      let stderr = "";
      child.stdout.on("data", (d) => (stdout += d));
      child.stderr.on("data", (d) => (stderr += d));
      child.on("error", reject);
      child.on("close", (status) => resolve({ status, stdout, stderr }));
      child.stdin.end("");
    });

  it("registers once for the whole list and writes it to .env.local", { skip: process.platform === "win32" }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-multi-"));
    try {
      const res = await run(dir, ["init", "--service", "GigPulse,devpulse", "--domain", "gigpulse.example.com", "--auth-url", authUrl], {
        DAYWALKER_API_KEY: "srv_live_multi",
      });
      assert.strictEqual(res.status, 0, res.stderr);
      assert.strictEqual(bodies.at(-1).serviceSlug, undefined);
      assert.match(fs.readFileSync(path.join(dir, ".env.local"), "utf8"), /^DAYWALKER_SERVICE_SLUG="gigpulse,devpulse"$/m);

      const check = await run(dir, ["check"], { DAYWALKER_API_KEY: "srv_live_multi" });
      assert.match(check.stdout, /Services: gigpulse, devpulse \(default: gigpulse\)/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("rejects an invalid slug in the list", { skip: process.platform === "win32" }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-multi-"));
    try {
      const res = await run(dir, ["init", "--service", "good,bad slug!", "--skip-register"]);
      assert.notStrictEqual(res.status, 0);
      assert.match(res.stderr, /--service must be/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
