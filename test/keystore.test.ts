import { describe, it } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Daywalker, generateSigningKey, importSigningKey, verifyRequestSignature, type PublicJwk, type StoredSigningKey } from "../src/index.js";
import { envKeyStore, memoryKeyStore, parseStoredSigningKey } from "../src/keystore/index.js";
import { fileKeyStore } from "../src/keystore/file.js";
import { withOAuth } from "./helpers/oauth.js";

const env = {};
const DOMAIN = "app.example.com";

/** A fake Daywalker: records key registrations and the validate requests it receives. */
function fakeDaywalker(options: { register?: () => Response | Promise<Response> } = {}) {
  const registered: { authorization: string | null; body: any }[] = [];
  const validated: { headers: Headers; body: string }[] = [];
  const fetch = withOAuth(async (url, init) => {
    const href = String(url);
    if (href.endsWith("/api/v1/keys/register")) {
      const body = JSON.parse(String(init?.body));
      registered.push({ authorization: new Headers(init?.headers).get("authorization"), body });
      return (await options.register?.()) ?? Response.json({ id: "sk_1", keyId: body.keyId, status: "ACTIVE" }, { status: 201 });
    }
    validated.push({ headers: new Headers(init?.headers), body: String(init?.body) });
    return Response.json({ valid: true, serviceSlug: "svc", tenantId: "t" });
  });
  return { fetch, registered, validated };
}

async function signedBy(req: { headers: Headers; body: string }, publicKey: PublicJwk) {
  return verifyRequestSignature({
    method: "POST",
    path: "/api/v1/tokens/validate",
    authority: "auth.daywalker.dev",
    headers: req.headers,
    body: req.body,
    publicKey,
    replayCheck: false,
  });
}

const client = (extra: Record<string, unknown>) => new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", domain: DOMAIN, ...extra });

describe("Auto-provisioning with a key store", () => {
  it("generates, registers and stores a key on first use, then signs with it", async () => {
    const store = memoryKeyStore();
    const dw = fakeDaywalker();
    const a = client({ keyStore: store, fetch: dw.fetch });
    assert.equal((await a.validateToken("tok")).ok, true);

    assert.equal(dw.registered.length, 1);
    const reg = dw.registered[0];
    assert.equal(reg.authorization, "Bearer srv_live_service_key");
    assert.equal(reg.body.domain, DOMAIN);
    assert.equal(reg.body.serviceSlug, "svc");
    assert.equal("d" in reg.body.publicKey, false);

    const stored = (await store.load())!;
    assert.equal(stored.keyId, reg.body.keyId);
    assert.equal(stored.domain, DOMAIN);
    const check = await signedBy(dw.validated[0], reg.body.publicKey);
    assert.equal(check.valid, true, check.error);
    assert.equal(check.keyid, stored.keyId);

    // Another process with the same store reuses the key: no second registration.
    const b = client({ keyStore: store, fetch: dw.fetch });
    assert.deepEqual(await b.provisionSigningKey(), { source: "keyStore", keyId: stored.keyId });
    assert.equal(dw.registered.length, 1);
  });

  it("settles concurrent first starts on one stored key and reports the orphan", async () => {
    const store = memoryKeyStore();
    // Slow registration, so both instances register before either saves (the worst case).
    const dw = fakeDaywalker({ register: () => new Promise((r) => setTimeout(() => r(Response.json({}, { status: 201 })), 30)) });
    const warnings: string[] = [];
    const warn = console.warn;
    console.warn = (msg: string) => warnings.push(msg);
    try {
      const [a, b] = await Promise.all([client({ keyStore: store, fetch: dw.fetch }).provisionSigningKey(), client({ keyStore: store, fetch: dw.fetch }).provisionSigningKey()]);
      const stored = (await store.load())!;
      assert.equal(a!.keyId, stored.keyId);
      assert.equal(b!.keyId, stored.keyId);
      assert.equal(dw.registered.length, 2);
      assert.equal(warnings.length, 1);
      const orphan = dw.registered.map((r) => r.body.keyId).find((k) => k !== stored.keyId);
      assert.match(warnings[0], new RegExp(`${orphan}.*Revoke it`));
    } finally {
      console.warn = warn;
    }
  });

  it("stores nothing when registration fails, reports it as an outage, and retries next time", async () => {
    const store = memoryKeyStore();
    let fail = true;
    const dw = fakeDaywalker({ register: () => (fail ? Response.json({ error: "DOMAIN_MISMATCH", message: "Domain not on API key allowlist" }, { status: 403 }) : Response.json({}, { status: 201 })) });
    const dwClient = client({ keyStore: store, fetch: dw.fetch });
    const res = await dwClient.validateToken("tok");
    assert.deepEqual(res.ok ? null : [res.status, res.error], [503, "SERVICE_UNAVAILABLE"]);
    assert.match(res.ok ? "" : res.message, /KEY_REGISTRATION_FAILED.*allowlist/);
    assert.equal(await store.load(), null);
    assert.equal(dw.validated.length, 0);

    fail = false;
    assert.equal((await dwClient.validateToken("tok")).ok, true);
    assert.ok(await store.load());
  });

  it("refuses to provision without a domain or API key, and never calls Daywalker", async () => {
    const dw = fakeDaywalker();
    const noDomain = new Daywalker({ env, apiKey: "srv_live_service_key", serviceSlug: "svc", keyStore: memoryKeyStore(), fetch: dw.fetch });
    const res = await noDomain.validateToken("tok");
    assert.deepEqual(res.ok ? null : [res.status, res.error], [500, "CONFIGURATION_ERROR"]);
    assert.match((await noDomain.selfCheck()).problems.join("\n"), /DAYWALKER_DOMAIN/);
    await assert.rejects(new Daywalker({ env, domain: DOMAIN, keyStore: memoryKeyStore(), fetch: dw.fetch }).provisionSigningKey(), /DAYWALKER_API_KEY/);
    assert.equal(dw.registered.length, 0);
  });

  it("selfCheck reads the store but never provisions", async () => {
    const dw = fakeDaywalker();
    const result = await client({ keyStore: memoryKeyStore(), fetch: dw.fetch }).selfCheck();
    assert.equal(result.ok, true);
    assert.equal(result.signing, true);
    assert.equal(result.keyId, null);
    assert.equal(dw.registered.length, 0);
  });

  it("uses a read-only env store as is, and refuses to provision into it", async () => {
    const key = await generateSigningKey();
    const dw = fakeDaywalker();
    const store = envKeyStore({ DAYWALKER_SIGNING_KEY: key.privateKeyPkcs8Base64, DAYWALKER_KEY_ID: key.publicJwk.kid, DAYWALKER_DOMAIN: DOMAIN });
    assert.equal((await client({ keyStore: store, fetch: dw.fetch }).validateToken("tok")).ok, true);
    assert.equal((await signedBy(dw.validated[0], key.publicJwk)).valid, true);
    assert.equal(dw.registered.length, 0);

    await assert.rejects(client({ keyStore: envKeyStore({}), fetch: dw.fetch }).provisionSigningKey(), /read-only/);
  });

  it("refuses a stored key that doesn't match its keyId, its domain, or the record format", async () => {
    const key = await generateSigningKey();
    const good: StoredSigningKey = { version: 1, keyId: key.publicJwk.kid, domain: DOMAIN, privateKeyPkcs8Base64: key.privateKeyPkcs8Base64!, createdAt: 1 };
    const other = await generateSigningKey();
    const dw = fakeDaywalker();

    await assert.rejects(client({ keyStore: memoryKeyStore({ ...good, keyId: other.publicJwk.kid }), fetch: dw.fetch }).provisionSigningKey(), /does not match its keyId/);
    await assert.rejects(client({ keyStore: memoryKeyStore({ ...good, domain: "other.example.com" }), fetch: dw.fetch }).provisionSigningKey(), /registered for other\.example\.com/);
    assert.throws(() => parseStoredSigningKey({ ...good, version: 2 }), /version/);
    assert.throws(() => parseStoredSigningKey({ ...good, domain: "localhost" }), /domain/);
    assert.throws(() => parseStoredSigningKey({ ...good, privateKeyPkcs8Base64: "not base64!" }), /private key/);
    assert.throws(() => parseStoredSigningKey({ ...good, keyId: 'x";evil' }), /keyId/);
    assert.equal(dw.registered.length, 0);
  });

  it("keeps the provisioned private key non-extractable", async () => {
    const key = await generateSigningKey();
    const imported = await importSigningKey(key.privateKeyPkcs8Base64!);
    assert.equal(imported.privateKey.extractable, false);
    assert.equal(imported.publicJwk.kid, key.publicJwk.kid);
  });
});

describe("fileKeyStore", () => {
  const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-keystore-"));
  const record = async (): Promise<StoredSigningKey> => {
    const key = await generateSigningKey();
    return { version: 1, keyId: key.publicJwk.kid, domain: DOMAIN, privateKeyPkcs8Base64: key.privateKeyPkcs8Base64!, createdAt: 1 };
  };

  it("creates the file atomically (exactly one of concurrent saves wins), 0600 in a 0700 directory", { skip: process.platform === "win32" }, async () => {
    const dir = tmp();
    try {
      const file = path.join(dir, "keys", "signing-key.json");
      const store = fileKeyStore({ path: file });
      assert.equal(await store.load(), null);
      const records = await Promise.all([record(), record(), record(), record()]);
      const results = await Promise.all(records.map((r) => store.saveIfAbsent!(r)));
      assert.equal(results.filter(Boolean).length, 1);
      const winner = records[results.indexOf(true)];
      assert.deepEqual(await store.load(), winner);
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
      assert.equal(fs.statSync(path.dirname(file)).mode & 0o777, 0o700);
      assert.deepEqual(fs.readdirSync(path.dirname(file)), ["signing-key.json"]); // no temp files left behind
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses symlinks and files others can read", { skip: process.platform === "win32" }, async () => {
    const dir = tmp();
    try {
      const real = path.join(dir, "real.json");
      fs.writeFileSync(real, JSON.stringify(await record()), { mode: 0o600 });
      const link = path.join(dir, "link.json");
      fs.symlinkSync(real, link);
      await assert.rejects(fileKeyStore({ path: link }).load(), /symlink/);
      assert.equal(await fileKeyStore({ path: link }).saveIfAbsent!(await record()), false);
      assert.deepEqual(JSON.parse(fs.readFileSync(real, "utf8")).version, 1);

      fs.chmodSync(real, 0o644);
      await assert.rejects(fileKeyStore({ path: real }).load(), /readable or writable by others/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("provisions end to end through a client", { skip: process.platform === "win32" }, async () => {
    const dir = tmp();
    try {
      const file = path.join(dir, ".daywalker", "signing-key.json");
      const dw = fakeDaywalker();
      assert.equal((await client({ keyStore: fileKeyStore({ path: file }), fetch: dw.fetch }).validateToken("tok")).ok, true);
      const again = await client({ keyStore: fileKeyStore({ path: file }), fetch: dw.fetch }).provisionSigningKey();
      assert.equal(again!.keyId, dw.registered[0].body.keyId);
      assert.equal(dw.registered.length, 1);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("External signer (KMS / HSM)", () => {
  const kms = async () => {
    const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
    const x = (publicKey.export({ format: "jwk" }) as { x: string }).x;
    const publicJwk: PublicJwk = { kty: "OKP", crv: "Ed25519", x, kid: "kms-key-1", alg: "EdDSA", use: "sig" };
    let calls = 0;
    const signer = {
      keyId: "kms-key-1",
      publicJwk,
      sign: async (data: Uint8Array) => (calls++, new Uint8Array(crypto.sign(null, data, privateKey))),
    };
    return { signer, publicJwk, calls: () => calls };
  };

  it("signs every request through the callback; no private key in the process", async () => {
    const { signer, publicJwk, calls } = await kms();
    const dw = fakeDaywalker();
    const dwClient = client({ signer, fetch: dw.fetch });
    assert.equal((await dwClient.validateToken("tok")).ok, true);
    const check = await signedBy(dw.validated[0], publicJwk);
    assert.equal(check.valid, true, check.error);
    assert.equal(check.keyid, "kms-key-1");
    assert.ok(calls() >= 3); // self-check, token grant, validate
    assert.deepEqual(await dwClient.provisionSigningKey(), { source: "signer", keyId: "kms-key-1" });
    assert.equal(dw.registered.length, 0);
  });

  it("checks the signer against its publicJwk before sending anything", async () => {
    const { signer } = await kms();
    const other = await generateSigningKey();
    const dw = fakeDaywalker();
    const res = await client({ signer: { ...signer, publicJwk: other.publicJwk }, fetch: dw.fetch }).validateToken("tok");
    assert.deepEqual(res.ok ? null : [res.status, res.error], [500, "CONFIGURATION_ERROR"]);
    assert.equal(dw.validated.length, 0);
  });

  it("refuses signatures of the wrong size, and can't be swapped after construction", async () => {
    const dw = fakeDaywalker();
    const short = client({ signer: { keyId: "k1", sign: async () => new Uint8Array(10) }, fetch: dw.fetch });
    assert.equal((await short.validateToken("tok")).ok, false);
    assert.equal(dw.validated.length, 0);

    const { signer, publicJwk } = await kms();
    const mutable = { ...signer };
    const dwClient = client({ signer: mutable, fetch: dw.fetch });
    mutable.sign = async () => new Uint8Array(64);
    assert.equal((await dwClient.validateToken("tok")).ok, true);
    assert.equal((await signedBy(dw.validated.at(-1)!, publicJwk)).valid, true);
    assert.throws(() => client({ signer: { keyId: 'bad"id', sign: signer.sign } }), /keyId/);
  });
});
