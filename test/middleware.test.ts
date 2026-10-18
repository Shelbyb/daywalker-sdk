import { describe, it } from "node:test";
import assert from "node:assert";
import { Daywalker } from "../src/index.js";
import {
  STATIC_FILE_EXTENSIONS,
  createDaywalkerMiddleware,
  createDaywalkerProxy,
  createDaywalkerServiceHealthMiddleware,
  createDaywalkerServiceHealthProxy,
  isStaticAssetPath,
  normalizePathname,
  sanitizeRedirectPath,
  withDaywalkerAuth,
} from "../src/next.js";
import { daywalkerAuth as webAuth, toAuthFailureResponse } from "../src/middleware.js";
import { daywalkerAuth as expressAuth } from "../src/express.js";
import type { ValidateResult } from "../src/types.js";
import { withOAuth } from "./helpers/oauth.js";

const env = {};
const NEXT = "x-middleware-next";

function countingClient(response: () => Response | Promise<Response>) {
  const state = { calls: 0 };
  const client = new Daywalker({
    env,
    apiKey: "srv_live_service_key",
    serviceSlug: "svc",
    maxRetries: 0,
    negativeCacheTtlMs: 0,
    fetch: withOAuth(async () => (state.calls++, response())),
  });
  return { client, state };
}

/** A client stub that returns a fixed validation result (for codes the real client cannot easily produce). */
function fixedClient(result: ValidateResult): Daywalker {
  return { validateToken: async () => result, validateServiceKey: async () => result, validateServiceCredentials: async () => result } as unknown as Daywalker;
}

const authed = (url: string, init: RequestInit = {}) =>
  new Request(url, { ...init, headers: { authorization: "Bearer tok_caller", ...(init.headers as Record<string, string>) } });

describe("Next middleware: static bypass is narrow and path-normalized", () => {
  it("only bypasses /_next/static, /_next/image and /favicon.ico by default", () => {
    for (const p of ["/_next/static/chunks/app.js", "/_next/image", "/favicon.ico"]) {
      assert.strictEqual(isStaticAssetPath(p), true, p);
    }
    for (const p of [
      "/admin/users/42.json.txt",
      "/users/123.js",
      "/dashboard/settings.png",
      "/logo.png",
      "/api/report.js",
      "/_next/data/build/page.json",
      "/%61pi/secret.js",
    ]) {
      assert.strictEqual(isStaticAssetPath(p), false, p);
    }
  });

  it("applies extension bypass only when opted in, and never to /api or /_next internals", () => {
    assert.strictEqual(isStaticAssetPath("/logo.png", STATIC_FILE_EXTENSIONS), true);
    assert.strictEqual(isStaticAssetPath("/fonts/a.woff2", ["woff2"]), true);
    assert.strictEqual(isStaticAssetPath("/fonts/a.woff2", [".png"]), false);
    for (const p of ["/api/x.png", "/%61pi/secret.js", "/API/../api/x.js", "/_next/data/x.js", "/_next/static%2F..%2Fadmin.js"]) {
      assert.strictEqual(isStaticAssetPath(p, STATIC_FILE_EXTENSIONS), false, p);
    }
  });

  it("normalizes paths: decodes once, collapses //, resolves dot segments, rejects encoded slashes", () => {
    assert.strictEqual(normalizePathname("/a//b/./c/../d"), "/a/b/d");
    assert.strictEqual(normalizePathname("/%61pi/secret.js"), "/api/secret.js");
    assert.strictEqual(normalizePathname("/_next/static/%2e%2e/%2e%2e/admin"), "/admin");
    assert.strictEqual(normalizePathname("/api/"), "/api/");
    assert.strictEqual(normalizePathname("/"), "/");
    assert.strictEqual(normalizePathname("/%2561pi"), "/%61pi");
    for (const p of ["/x%2Fy", "/x%5cy", "/x\\y", "/%E0%A4%A", "/a%00b", "relative"]) {
      assert.strictEqual(normalizePathname(p), null, p);
    }
  });

  it("authenticates extension-looking pages and encoded /api paths", async () => {
    const { client, state } = countingClient(() => Response.json({ error: "INVALID_TOKEN" }, { status: 401 }));
    const mw = createDaywalkerMiddleware({ client });
    for (const p of ["/admin/users/42.json.txt", "/users/123.js", "/dashboard/settings.png"]) {
      const res = await mw(authed(`https://app.example${p}`));
      assert.strictEqual(res.headers.get(NEXT), null, p);
      assert.strictEqual(res.status, 307, p);
    }
    assert.strictEqual(state.calls, 3);

    // `/%61pi/...` is routed as `/api/...`: JSON, not a redirect, even with protectApiOnly.
    const apiOnly = createDaywalkerMiddleware({ client, protectApiOnly: true, staticFileExtensions: STATIC_FILE_EXTENSIONS });
    const res = await apiOnly(new Request("https://app.example/%61pi/secret.js"));
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.headers.get("content-type"), "application/json");

    // Paths that cannot be normalized are never bypassed and are treated as API routes.
    const encoded = await apiOnly(new Request("https://app.example/_next/static%2F..%2Fadmin.js"));
    assert.strictEqual(encoded.status, 401);

    // Opted-in extensions pass, built-ins pass.
    assert.strictEqual((await apiOnly(new Request("https://app.example/logo.png"))).headers.get(NEXT), "1");
    assert.strictEqual((await mw(new Request("https://app.example/_next/static/chunks/a.js"))).headers.get(NEXT), "1");
  });

  it("matches bypassPaths against the normalized path", async () => {
    const { client } = countingClient(() => Response.json({}, { status: 401 }));
    const mw = createDaywalkerMiddleware({ client, bypassPaths: ["/public"] });
    assert.strictEqual((await mw(new Request("https://app.example/public/a"))).headers.get(NEXT), "1");
    assert.strictEqual((await mw(new Request("https://app.example/%70ublic/a"))).headers.get(NEXT), "1");
    assert.strictEqual((await mw(new Request("https://app.example/public%2F..%2Fadmin"))).headers.get(NEXT), null);
    assert.strictEqual((await mw(new Request("https://app.example/publicity"))).headers.get(NEXT), null);
  });
});

describe("Next middleware: redirects", () => {
  it("sanitizeRedirectPath rejects whitespace, control chars, backslashes and cross-origin targets", () => {
    for (const p of ["/\t/evil.com", "/\n/evil.com", "/\u000b/evil.com", "/ /evil.com", "/\\evil.com", "//evil.com", "/ /x", "https://evil.com", "evil.com", ""]) {
      assert.strictEqual(sanitizeRedirectPath(p), null, JSON.stringify(p));
    }
    for (const p of ["/dashboard", "/dashboard?tab=security", "/%09/evil.com", "/a/b#c"]) {
      const s = sanitizeRedirectPath(p);
      assert.strictEqual(s, p);
      assert.strictEqual(new URL(s!, "https://app.example").origin, "https://app.example");
    }
  });

  it("puts only a fixed error code and status in the error-page URL, never the message", async () => {
    const mw = createDaywalkerMiddleware({
      client: fixedClient({ ok: false, error: "INVALID_TOKEN", status: 401, message: "expected slug acme-internal <b>call 555</b>" }),
    });
    const res = await mw(authed("https://app.example/dashboard?tab=1"));
    assert.strictEqual(res.status, 307);
    const loc = new URL(res.headers.get("location")!);
    assert.strictEqual(loc.pathname, "/service-error");
    assert.strictEqual(loc.searchParams.get("error"), "INVALID_TOKEN");
    assert.strictEqual(loc.searchParams.get("status"), "401");
    assert.strictEqual(loc.searchParams.get("message"), null);
    assert.strictEqual(loc.searchParams.get("from"), "/dashboard?tab=1");
    assert.ok(!loc.href.includes("acme-internal"));

    const odd = createDaywalkerMiddleware({ client: fixedClient({ ok: false, error: "<script>", status: 401, message: "x" }) });
    const oddLoc = new URL((await odd(authed("https://app.example/x"))).headers.get("location")!);
    assert.strictEqual(oddLoc.searchParams.get("error"), "UNAUTHORIZED");
  });
});

describe("Next middleware: /api detection and Host allowlist", () => {
  it("treats exactly /api as an API route", async () => {
    const { client } = countingClient(() => Response.json({}, { status: 401 }));
    const apiOnly = createDaywalkerMiddleware({ client, protectApiOnly: true });
    const res = await apiOnly(new Request("https://app.example/api"));
    assert.strictEqual(res.status, 401);
    assert.strictEqual(res.headers.get(NEXT), null);
    assert.strictEqual((await apiOnly(new Request("https://app.example/dashboard"))).headers.get(NEXT), "1");

    const full = createDaywalkerMiddleware({ client });
    const json = await full(new Request("https://app.example/api"));
    assert.strictEqual(json.status, 401);
    assert.strictEqual(json.headers.get("location"), null);
    assert.strictEqual((await json.json()).error, "INVALID_TOKEN");
  });

  it("refuses requests without a Host header when allowedHosts is set", async () => {
    const { client } = countingClient(() => Response.json({ valid: true, serviceSlug: "svc", tenantId: "t" }));
    const mw = createDaywalkerMiddleware({ client, allowedHosts: ["app.example"] });
    assert.strictEqual((await mw(authed("https://app.example/dashboard"))).status, 403);
    assert.strictEqual((await mw(authed("https://app.example/dashboard", { headers: { host: "evil.example" } }))).status, 403);
    const ok = await mw(authed("https://app.example/dashboard", { headers: { host: "app.example:443" } }));
    assert.strictEqual(ok.headers.get(NEXT), "1");
  });
});

describe("Adapters map failures to the right status", () => {
  const cases: Array<{ name: string; result: ValidateResult; status: number; retryAfter?: string }> = [
    { name: "revoked token", result: { ok: false, error: "REVOKED", status: 401, message: "Token revoked" }, status: 401 },
    { name: "rate limited", result: { ok: false, error: "RATE_LIMITED", status: 429, message: "slow down", retryAfter: 7 }, status: 429, retryAfter: "7" },
    { name: "network error", result: { ok: false, error: "NETWORK_ERROR", status: 503, message: "Could not reach auth.internal:8443" }, status: 503 },
    { name: "service unavailable", result: { ok: false, error: "SERVICE_UNAVAILABLE", status: 503, message: "down", retryAfter: 30 }, status: 503, retryAfter: "30" },
    { name: "upstream 502", result: { ok: false, error: "INVALID_TOKEN", status: 502, message: "Validation failed with HTTP 502" }, status: 503 },
    { name: "configuration error", result: { ok: false, error: "CONFIGURATION_ERROR", status: 500, message: "DAYWALKER_API_KEY is not set" }, status: 500 },
  ];

  it("toAuthFailureResponse hides outage and configuration details", () => {
    const unavailable = toAuthFailureResponse({ ok: false, error: "NETWORK_ERROR", status: 503, message: "Could not reach auth.internal:8443" });
    assert.strictEqual(unavailable.status, 503);
    assert.strictEqual(unavailable.error, "NETWORK_ERROR");
    assert.ok(!unavailable.message.includes("auth.internal"));
    const config = toAuthFailureResponse({ ok: false, error: "CONFIGURATION_ERROR", status: 500, message: "DAYWALKER_API_KEY is not set" });
    assert.deepStrictEqual([config.status, config.message.includes("DAYWALKER_API_KEY")], [500, false]);
    assert.strictEqual(toAuthFailureResponse({ ok: false, error: "SOMETHING_NEW", status: 504, message: "" }).error, "SERVICE_UNAVAILABLE");
  });

  for (const c of cases) {
    it(`${c.name} -> ${c.status} in every adapter`, async () => {
      const client = fixedClient(c.result);

      const next = await createDaywalkerMiddleware({ client })(authed("https://app.example/api/data"));
      const route = await withDaywalkerAuth(async () => Response.json({}), { client })(authed("https://app.example/api/data"));
      const web = (await webAuth({ client })({ req: { headers: new Headers({ authorization: "Bearer t" }) } }, async () => undefined)) as Response;

      let honoArgs: unknown[] = [];
      await webAuth({ client })({ req: { header: () => "Bearer t" }, json: (...a: unknown[]) => ((honoArgs = a), new Response()) }, async () => undefined);

      const expressRes = { code: 0, headers: {} as Record<string, string>, body: undefined as any };
      await expressAuth({ client })(
        { headers: { authorization: "Bearer t" } },
        {
          setHeader: (n: string, v: string) => (expressRes.headers[n] = v),
          status(code: number) {
            expressRes.code = code;
            return this;
          },
          json: (b: unknown) => (expressRes.body = b),
          end: () => undefined,
        }
      );

      for (const [label, res] of [["next", next], ["route", route], ["web", web]] as const) {
        assert.strictEqual(res.status, c.status, label);
        assert.strictEqual(res.headers.get("retry-after"), c.retryAfter ?? null, label);
        const body = await res.json();
        if (c.status === 500) assert.ok(!JSON.stringify(body).includes("DAYWALKER_API_KEY"), label);
        if (c.status === 503) assert.ok(!JSON.stringify(body).includes("auth.internal"), label);
      }
      assert.strictEqual(honoArgs[1], c.status);
      assert.strictEqual(expressRes.code, c.status);
      assert.strictEqual(expressRes.headers["Retry-After"], c.retryAfter);
    });
  }

  it("an unreachable Daywalker Auth yields 503, not 401", async () => {
    const { client } = countingClient(() => {
      throw new TypeError("ECONNREFUSED");
    });
    const web = (await webAuth({ client })({ req: { headers: new Headers({ authorization: "Bearer tok" }) } }, async () => undefined)) as Response;
    assert.strictEqual(web.status, 503);
    const { client: badGateway } = countingClient(() => new Response("<html>bad gateway</html>", { status: 502 }));
    const route = await withDaywalkerAuth(async () => Response.json({}), badGateway)(authed("https://app.example/api/x"));
    assert.strictEqual(route.status, 503);
  });

  it("UI routes redirect to the error page with the mapped status on outages", async () => {
    const mw = createDaywalkerMiddleware({ client: fixedClient({ ok: false, error: "NETWORK_ERROR", status: 503, message: "x" }) });
    const loc = new URL((await mw(authed("https://app.example/dashboard"))).headers.get("location")!);
    assert.strictEqual(loc.searchParams.get("status"), "503");
    assert.strictEqual(loc.searchParams.get("error"), "NETWORK_ERROR");
  });
});

describe("Next.js 16 proxy aliases", () => {
  it("exports proxy-named factories identical to the middleware ones", () => {
    assert.strictEqual(createDaywalkerProxy, createDaywalkerMiddleware);
    assert.strictEqual(createDaywalkerServiceHealthProxy, createDaywalkerServiceHealthMiddleware);
  });
});
