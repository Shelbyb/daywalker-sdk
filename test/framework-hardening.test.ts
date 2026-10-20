import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { daywalkerAuth as expressAuth } from "../src/express.js";
import { createDaywalkerMiddleware } from "../src/next.js";
import { assertSecureUrl } from "../src/secure-url.js";
import { createManagementClient } from "../src/management.js";
import { fileKeyStore } from "../src/keystore/file.js";

const failing = { validateToken: async () => ({ ok: false, error: "INVALID_TOKEN", status: 401, message: "bad" }) } as any;

describe("framework adapter hardening", () => {
  it("treats /API/* as an API route under protectApiOnly", async () => {
    const mw = createDaywalkerMiddleware({ client: failing, protectApiOnly: true });
    for (const p of ["/API/secret", "/Api/x", "/%41PI/x"]) {
      const res = await mw(new Request(`https://a.example${p}`));
      assert.equal(res.status, 401, p);
      assert.equal(res.headers.get("x-middleware-next"), null, p);
    }
    assert.equal((await mw(new Request("https://a.example/dashboard"))).headers.get("x-middleware-next"), "1");
  });

  it("express adapter answers 503 (no internals) when validation throws", async () => {
    const throwing = { validateToken: async () => { throw new Error("secret internal detail"); } } as any;
    let status = 0;
    let body: any;
    let nextCalled = false;
    const res = { setHeader() {}, status(c: number) { status = c; return res; }, json(b: unknown) { body = b; }, end() {} };
    await expressAuth({ client: throwing })({ method: "GET", url: "/x", headers: { authorization: "Bearer tok" } }, res as any, () => { nextCalled = true; });
    assert.equal(status, 503);
    assert.equal(nextCalled, false);
    assert.doesNotMatch(JSON.stringify(body), /secret internal detail/);
  });
});

describe("assertSecureUrl", () => {
  it("allows https and loopback http only", () => {
    for (const ok of ["https://a.example", "HTTPS://A.EXAMPLE", "http://localhost:3000", "HTTP://LOCALHOST", "http://127.0.0.1", "http://[::1]:8080"]) {
      assert.doesNotThrow(() => assertSecureUrl("u", ok), ok);
    }
    for (const bad of ["http://localhost.evil.com", "http://evil.com", "http://localhost@evil.com", "https://u:p@a.example", "http://[::2]", "ftp://localhost", "localhost"]) {
      assert.throws(() => assertSecureUrl("u", bad), undefined, bad);
    }
  });

  it("does not echo secrets from the URL in its errors", () => {
    assert.throws(() => assertSecureUrl("u", "http://evil.com/?key=sk_live_secret"), (e: Error) => !e.message.includes("sk_live_secret"));
    assert.throws(() => assertSecureUrl("u", "nope sk_live_secret"), (e: Error) => !e.message.includes("sk_live_secret"));
  });
});

describe("management client authUrl", () => {
  it("refuses cleartext, credentials, query and fragment", () => {
    for (const bad of ["http://auth.example.com", "https://u:p@auth.example.com", "https://auth.example.com?x=1", "https://auth.example.com#f"]) {
      assert.throws(() => createManagementClient({ authUrl: bad, sessionToken: "jwt" }), undefined, bad);
    }
    assert.doesNotThrow(() => createManagementClient({ authUrl: "http://localhost:3000", sessionToken: "jwt" }));
    assert.doesNotThrow(() => createManagementClient({ authUrl: "https://auth.example.com/", sessionToken: "jwt" }));
  });
});

describe("fileKeyStore", () => {
  it("does not leak key file content when the JSON is corrupt", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dw-ks-"));
    const file = path.join(dir, "signing-key.json");
    fs.writeFileSync(file, '{"privateKeyPkcs8Base64":"MC4CAQAwBQYDK2VwBCIEIsecretsecret', { mode: 0o600 });
    await assert.rejects(fileKeyStore({ path: file }).load(), (e: Error) => !e.message.includes("secretsecret") && /not valid JSON/.test(e.message));
  });

  it("refuses a FIFO without blocking", { skip: process.platform === "win32" }, async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "dw-ks-"));
    const file = path.join(dir, "signing-key.json");
    execFileSync("mkfifo", ["-m", "600", file]);
    await assert.rejects(fileKeyStore({ path: file }).load(), /not a regular file/);
  });
});
