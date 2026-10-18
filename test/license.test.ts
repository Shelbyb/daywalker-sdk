import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { Daywalker, DaywalkerAuthError, generateSigningKey } from "../src/index.js";
import { fakeAccessToken } from "./helpers/oauth.js";

const SECRET = "s".repeat(64);
const hex = (slug: string, keyId: string, win: number) =>
  Buffer.from(crypto.hkdfSync("sha256", Buffer.from(SECRET), Buffer.from(`${slug}${keyId}${win}`), Buffer.from("daywalker-license-v1"), 32)).toString("hex");
const WINDOW = 3_600_000;

function seal(licenseKey: string, payload: object) {
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv("aes-256-gcm", Buffer.from(licenseKey, "hex"), iv);
  const ct = Buffer.concat([c.update(JSON.stringify(payload), "utf8"), c.final()]);
  return { iv: iv.toString("base64"), tag: c.getAuthTag().toString("base64"), ciphertext: ct.toString("base64") };
}

async function setup(opts: { withLicense?: boolean; tokenError?: Response; bundleError?: Response; bundleWindowOffset?: number } = {}) {
  const key = await generateSigningKey();
  const calls: string[] = [];
  let grants = 0;
  const fetch = (async (url: string | URL | Request, init?: RequestInit) => {
    const u = new URL(String(url));
    calls.push(u.pathname);
    if (u.pathname === "/api/v1/oauth/token") {
      if (opts.tokenError) return opts.tokenError.clone();
      grants++;
      const win = Math.floor(Date.now() / WINDOW);
      const body: Record<string, unknown> = {
        access_token: fakeAccessToken({ services: ["svc"], aud: ["svc"], n: grants }),
        token_type: "DPoP", expires_in: 900, expires_at: Math.floor(Date.now() / 1000) + 900,
        refresh_token: `rt_${grants}`, refresh_expires_in: 3600, services: ["svc"],
      };
      if (opts.withLicense !== false && JSON.parse(String(init?.body)).grant_type === "client_credentials") {
        const lic = { licenseKey: hex("svc", key.publicJwk.kid, win), expiresAt: new Date(Date.now() + WINDOW).toISOString() };
        Object.assign(body, { ...lic, licenseExpiresAt: lic.expiresAt, licenses: { svc: lic } });
      }
      return Response.json(body);
    }
    if (u.pathname === "/api/v1/services/svc/bundle") {
      if (opts.bundleError) return opts.bundleError.clone();
      const win = Math.floor(Date.now() / WINDOW) + (opts.bundleWindowOffset ?? 0);
      const payload = { serviceSlug: "svc", dataKeySalt: "abc", features: { stage: "LIVE" }, issuedAt: new Date().toISOString(), expiresAt: new Date(Date.now() + WINDOW).toISOString() };
      return Response.json({ serviceSlug: "svc", bundle: seal(hex("svc", key.publicJwk.kid, win), payload) });
    }
    return Response.json({});
  }) as typeof globalThis.fetch;
  const client = new Daywalker({ env: {}, apiKey: "srv_live_k", serviceSlug: "svc", domain: "app.example.com", signingKey: key as any, fetch });
  return { client, calls, key };
}

describe("License and config bundle", () => {
  it("getLicense returns the key from the grant and caches it", async () => {
    const { client, calls } = await setup();
    const a = await client.getLicense();
    assert.match(a.licenseKey, /^[0-9a-f]{64}$/);
    assert.equal(a.serviceSlug, "svc");
    await client.getLicense();
    assert.equal(calls.filter((p) => p.endsWith("/oauth/token")).length, 1);
    await client.getLicense({ forceRefresh: true });
    assert.equal(calls.filter((p) => p.endsWith("/oauth/token")).length, 2);
  });

  it("getLicense never exposes the key through tokens or JSON", async () => {
    const { client } = await setup();
    const lic = await client.getLicense();
    const tokens = await client.getTokens();
    assert.ok(!JSON.stringify(tokens).includes(lic.licenseKey));
    assert.ok(!JSON.stringify(client).includes(lic.licenseKey));
  });

  it("throws LICENSE_UNAVAILABLE when Daywalker grants no license", async () => {
    const { client } = await setup({ withLicense: false });
    await assert.rejects(client.getLicense(), (e: any) => e instanceof DaywalkerAuthError && e.code === "LICENSE_UNAVAILABLE");
  });

  it("surfaces SERVICE_REVOKED from the grant", async () => {
    const { client } = await setup({ tokenError: Response.json({ error: "SERVICE_REVOKED", code: "SERVICE_REVOKED", message: "revoked" }, { status: 403 }) });
    await assert.rejects(client.getLicense(), (e: any) => e.status === 403 && e.code === "SERVICE_REVOKED");
  });

  it("fetchBundle opens the sealed bundle and caches it", async () => {
    const { client, calls } = await setup();
    const b = await client.fetchBundle();
    assert.equal(b.dataKeySalt, "abc");
    assert.equal(b.features.stage, "LIVE");
    await client.fetchBundle();
    assert.equal(calls.filter((p) => p.endsWith("/bundle")).length, 1);
  });

  it("fetchBundle fails with BUNDLE_UNREADABLE when sealed under another key", async () => {
    const { client } = await setup({ bundleWindowOffset: -5 });
    await assert.rejects(client.fetchBundle(), (e: any) => e.code === "BUNDLE_UNREADABLE");
  });

  it("fetchBundle surfaces SERVICE_REVOKED", async () => {
    const { client } = await setup({ bundleError: Response.json({ error: "SERVICE_REVOKED", message: "revoked" }, { status: 403 }) });
    await assert.rejects(client.fetchBundle(), (e: any) => e.status === 403 && e.code === "SERVICE_REVOKED");
  });

  it("fetchBundle reports the status, the service's message and a fallback code when the service sent none", async () => {
    const { client } = await setup({ bundleError: Response.json({ error: "Unauthorized", message: "Authentication required" }, { status: 401 }) });
    await assert.rejects(
      client.fetchBundle(),
      (e: any) => e.status === 401 && e.code === "Unauthorized" && /svc/.test(e.message) && /HTTP 401/.test(e.message) && /Authentication required/.test(e.message)
    );
  });

  it("fetchBundle derives a code from the status when the body is not JSON", async () => {
    const { client } = await setup({ bundleError: new Response("<html>bad gateway</html>", { status: 502 }) });
    await assert.rejects(client.fetchBundle(), (e: any) => e.status === 502 && e.code === "SERVICE_UNAVAILABLE" && /HTTP 502/.test(e.message));
  });
});
