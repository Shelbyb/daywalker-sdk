import test from "node:test";
import assert from "node:assert/strict";
import { createManagementClient, accessTokenServiceLimits, accessTokenServices, createDpopProof, generateDpopKey } from "../src/index.js";

test("management client sends session JWT and JSON", async () => {
  const calls: { url: string; init: any }[] = [];
  const client = createManagementClient({
    authUrl: "https://auth.example.com/",
    sessionToken: "sess",
    fetch: (async (url: any, init: any) => {
      calls.push({ url: String(url), init });
      return new Response(JSON.stringify({ id: "t1" }), { status: 200 });
    }) as any,
  });
  await client.createToken({ name: "n", serviceId: "s", additionalServiceIds: ["a"], expiresAt: new Date(0) });
  await client.getTokenLogs("t1", { limit: 5 });
  assert.equal(calls[0].url, "https://auth.example.com/api/v1/tokens");
  assert.equal(calls[0].init.headers.Authorization, "Bearer sess");
  assert.equal(JSON.parse(calls[0].init.body).expiresAt, "1970-01-01T00:00:00.000Z");
  assert.equal(calls[1].url, "https://auth.example.com/api/v1/tokens/t1/logs?limit=5");
  assert.throws(() => client.getToken("../x"), /invalid id/);
});

test("management errors carry status and code", async () => {
  const client = createManagementClient({
    authUrl: "https://auth.example.com",
    sessionToken: "s",
    fetch: (async () => new Response(JSON.stringify({ message: "nope", code: "X" }), { status: 403 })) as any,
  });
  await assert.rejects(client.listTokens(), (e: any) => e.status === 403 && e.code === "X");
});

test("claims helpers and DPoP proof", async () => {
  assert.deepEqual(accessTokenServices({ aud: "A" }), ["a"]);
  assert.deepEqual(accessTokenServiceLimits({ service_limits: { A: { rateLimitPerMinute: 5 }, b: 1 } }), { a: { rateLimitPerMinute: 5 } });
  const proof = await createDpopProof(await generateDpopKey(), { method: "post", url: "https://x.test/p?q=1", accessToken: "tok" });
  const claims = JSON.parse(Buffer.from(proof.split(".")[1], "base64url").toString());
  assert.equal(claims.htm, "POST");
  assert.equal(claims.htu, "https://x.test/p");
  assert.ok(claims.ath);
});
