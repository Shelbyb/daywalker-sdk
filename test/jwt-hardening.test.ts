import { describe, it } from "node:test";
import assert from "node:assert";
import crypto from "node:crypto";
import { verifyJwtLease, buildTokenCookie, clearTokenCookie, daywalkerCookies, accessTokenUser } from "../src/index.js";

describe("access token verification", () => {
  const { privateKey, publicKey } = crypto.generateKeyPairSync("ed25519");
  const pub = publicKey.export({ format: "jwk" }) as any;
  const now = Math.floor(Date.now() / 1000);
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString("base64url");
  const mk = (payload: Record<string, unknown>, header: Record<string, unknown> = {}) => {
    const h = enc({ alg: "EdDSA", typ: "at+jwt", ...header });
    const p = enc({ iss: "https://auth.daywalker.dev", aud: ["svc"], jti: "j", exp: now + 600, ...payload });
    return `${h}.${p}.${crypto.sign(null, Buffer.from(`${h}.${p}`), privateKey).toString("base64url")}`;
  };
  const verify = (token: string, extra = {}) =>
    verifyJwtLease({ token, publicKey: pub, expectedServiceSlug: "svc", expectedIssuer: "https://auth.daywalker.dev", currentTime: now, ...extra });

  it("accepts a well-formed RFC 9068 access token", async () => {
    assert.strictEqual((await verify(mk({}))).valid, true);
  });

  it("rejects alg none and HMAC algorithms", async () => {
    const none = `${enc({ alg: "none", typ: "at+jwt" })}.${enc({ aud: ["svc"], jti: "j", exp: now + 60 })}.`;
    assert.match((await verify(none)).error!, /Unsupported JWT alg/);
    assert.match((await verify(mk({}, { alg: "HS256" }))).error!, /Unsupported JWT alg/);
  });

  it("requires a jti and never accepts a refresh token", async () => {
    assert.match((await verify(mk({ jti: undefined }))).error!, /jti/);
    assert.match((await verify(mk({}, { typ: "rt+jwt" }))).error!, /typ/);
  });

  it("tolerates at most 30 seconds of clock skew, even if asked for more", async () => {
    assert.strictEqual((await verify(mk({ exp: now - 29 }), { clockSkewSeconds: 300 })).valid, true);
    assert.match((await verify(mk({ exp: now - 31 }), { clockSkewSeconds: 300 })).error!, /expired/);
  });

  it("reads the user object only from a verified payload", async () => {
    const res = await verify(mk({ user: { id: "018f3c2a-7b4e-7c53-9d3b-2f6d1c7e9a10", name: "Ada", email: "ada@example.com" } }));
    assert.deepStrictEqual(accessTokenUser(res.payload!), { id: "018f3c2a-7b4e-7c53-9d3b-2f6d1c7e9a10", name: "Ada", email: "ada@example.com" });
    assert.strictEqual(accessTokenUser({}), null);
  });
});

describe("token cookies", () => {
  it("is HttpOnly, Secure and SameSite=Strict by default", () => {
    assert.strictEqual(
      buildTokenCookie("dw_at", "a.b.c", { maxAge: 900 }),
      "dw_at=a.b.c; Path=/; Max-Age=900; HttpOnly; Secure; SameSite=Strict"
    );
    assert.match(buildTokenCookie("dw_at", "a.b.c", { maxAge: 9, sameSite: "Lax" }), /SameSite=Lax$/);
  });

  it("refuses attribute injection", () => {
    assert.throws(() => buildTokenCookie("dw_at", "a; Domain=evil.com", { maxAge: 1 }), TypeError);
    assert.throws(() => buildTokenCookie("dw at", "a.b.c", { maxAge: 1 }), TypeError);
    assert.throws(() => buildTokenCookie("dw_at", "a.b.c", { maxAge: 1, path: "/x; HttpOnly" }), TypeError);
  });

  it("scopes the refresh token cookie to the refresh route and can clear cookies", () => {
    const [at, rt] = daywalkerCookies({ accessToken: "a.b.c", refreshToken: "d.e.f", expiresIn: 900, refreshExpiresIn: 100 });
    assert.match(at, /^dw_at=a\.b\.c; Path=\/;/);
    assert.match(rt, /^dw_rt=d\.e\.f; Path=\/api\/auth\/refresh;/);
    assert.match(clearTokenCookie("dw_at"), /^dw_at=; Path=\/; Max-Age=0; HttpOnly/);
  });
});
