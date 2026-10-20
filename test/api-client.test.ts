import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { ApiAuthError, ApiClient, ApiProblemError, createApiClient, parseNextLink, parseRetryAfter, type ApiClientOptions } from "../src/api/index.js";

type Call = { url: string; init: RequestInit };
const json = (body: unknown, init: ResponseInit & { type?: string } = {}) => new Response(JSON.stringify(body), { ...init, headers: { "content-type": init.type ?? "application/json", ...(init.headers as Record<string, string>) } });
const token = (n = 1, expires_in = 3600) => json({ access_token: `tok${n}`, token_type: "Bearer", expires_in });
const isTok = (url: string) => url.endsWith("/oauth/token");
const fail = () => {
  throw new Error("should have failed");
};

function setup(handler: (url: string, init: RequestInit, n: number) => Response | Promise<Response>, over: Partial<ApiClientOptions> = {}) {
  const calls: Call[] = [];
  const sleeps: number[] = [];
  let clock = 1_000_000;
  const api = createApiClient({
    host: "https://dp.example.com/",
    clientId: "id@x",
    clientSecret: "s3cret/+",
    fetch: (async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return handler(url, init, calls.length);
    }) as unknown as typeof fetch,
    sleep: async (ms) => void sleeps.push(ms),
    now: () => clock,
    random: () => 1,
    ...over,
  });
  return { api, calls, sleeps, advance: (ms: number) => (clock += ms) };
}
const apiCalls = (calls: Call[]) => calls.filter((c) => !isTok(c.url));
const hdr = (c: Call) => c.init.headers as Record<string, string>;

describe("api client: auth", () => {
  it("validates options and hides credentials", () => {
    expect(() => new ApiClient({ host: "", clientId: "a", clientSecret: "b" })).toThrow(/host/);
    expect(() => new ApiClient({ host: "https://x", clientId: "", clientSecret: "b" })).toThrow(/clientId/);
    expect(() => new ApiClient({ host: "https://x", clientId: "a", clientSecret: "" })).toThrow(/clientSecret/);
    expect(() => new ApiClient({ host: "http://example.com", clientId: "a", clientSecret: "b" })).toThrow(/https/);
    expect(() => new ApiClient({ host: "https://u:p@example.com", clientId: "a", clientSecret: "b" })).toThrow(/credentials/);
    expect(() => new ApiClient({ host: "http://localhost:3000", clientId: "a", clientSecret: "b" })).not.toThrow();
    const { api } = setup(() => token());
    expect(JSON.stringify(api)).toBe('{"host":"https://dp.example.com","clientId":"id@x"}');
    expect(JSON.stringify(Object.values(api))).not.toMatch(/s3cret/);
  });

  it("fetches a token with Basic auth (secret never in the URL), caches, and refreshes early", async () => {
    let tokens = 0;
    const { api, calls, advance } = setup((url) => (isTok(url) ? token(++tokens) : json({ ok: true })), { scope: "flags:read" });
    await api.get("/api/v1/projects");
    await api.get("/api/v1/projects");
    const tokenCalls = calls.filter((c) => isTok(c.url));
    expect(tokenCalls).toHaveLength(1);
    const t = tokenCalls[0]!;
    expect(t.url).toBe("https://dp.example.com/oauth/token");
    expect(hdr(t).authorization).toBe(`Basic ${btoa("id%40x:s3cret%2F%2B")}`);
    expect(String(t.init.body)).toBe("grant_type=client_credentials&scope=flags%3Aread");
    for (const c of calls) expect(c.url).not.toMatch(/s3cret|secret|token=/);
    expect(hdr(apiCalls(calls)[0]!).authorization).toBe("Bearer tok1");
    advance(3600_000 - 30_000); // inside the 60s skew
    await api.get("/api/v1/projects");
    expect(calls.filter((c) => isTok(c.url))).toHaveLength(2);
    expect(hdr(apiCalls(calls)[2]!).authorization).toBe("Bearer tok2");
  });

  it("dedupes concurrent token fetches and refreshes once on 401", async () => {
    let n = 0;
    const { api } = setup((url, init) => {
      if (isTok(url)) return token(++n);
      return (init.headers as Record<string, string>).authorization === "Bearer tok1" ? json({ title: "Unauthorized", status: 401 }, { status: 401, type: "application/problem+json" }) : json({ ok: 1 });
    });
    const [a, b] = await Promise.all([api.get("/api/v1/a"), api.get("/api/v1/b")]);
    expect(a.data).toEqual({ ok: 1 });
    expect(b.data).toEqual({ ok: 1 });
    expect(n).toBe(2);
  });

  it("surfaces token endpoint errors", async () => {
    const bad = setup(() => json({ error: "invalid_client", error_description: "nope" }, { status: 401 }));
    const e = (await bad.api.get("/api/v1/x").then(fail, (x: unknown) => x)) as ApiAuthError;
    expect(e instanceof ApiAuthError).toBe(true);
    expect(e.code).toBe("invalid_client");
    expect(e.status).toBe(401);
    expect(e.message).toMatch(/nope/);
    const garbage = setup(() => new Response("<html>", { status: 502 }));
    expect(((await garbage.api.getAccessToken().then(fail, (x: unknown) => x)) as ApiAuthError).code).toBe("invalid_response");
    const net = setup(() => {
      throw new Error("dns");
    });
    expect(((await net.api.getAccessToken().then(fail, (x: unknown) => x)) as ApiAuthError).code).toBe("network_error");
    const noTtl = setup((url) => (isTok(url) ? json({ access_token: "t" }) : json({})));
    await noTtl.api.get("/api/v1/x");
  });
});

describe("api client: requests", () => {
  it("sends JSON bodies, query arrays and If-Match; exposes etag and rate limit", async () => {
    const { api, calls } = setup((url) => (isTok(url) ? token() : json({ id: 1 }, { headers: { etag: '"v2"', ratelimit: "limit=100, remaining=99, reset=30", "ratelimit-policy": "100;w=60" } })));
    const res = await api.patch<{ id: number }>("/api/v1/flags/x", { on: true }, { ifMatch: '"v1"', query: { env: ["a", "b"], skip: undefined, nul: null, n: 5, flag: true }, headers: { "x-extra": "1" } });
    const c = apiCalls(calls)[0]!;
    expect(c.url).toBe("https://dp.example.com/api/v1/flags/x?env=a&env=b&n=5&flag=true");
    expect(c.init.method).toBe("PATCH");
    expect(hdr(c)["if-match"]).toBe('"v1"');
    expect(hdr(c)["content-type"]).toBe("application/json");
    expect(hdr(c)["x-extra"]).toBe("1");
    expect(c.init.body).toBe('{"on":true}');
    expect(c.init.redirect).toBe("error");
    expect(res.etag).toBe('"v2"');
    expect(res.rateLimit).toEqual({ limit: 100, remaining: 99, resetSeconds: 30, policy: "100;w=60" });
    expect(res.status).toBe(200);
  });

  it("covers verb helpers, 204 and non-JSON bodies", async () => {
    const { api, calls } = setup((url, init) => {
      if (isTok(url)) return token();
      if (init.method === "DELETE") return new Response(null, { status: 204 });
      if (init.method === "PUT") return new Response("plain", { status: 200 });
      return json({}, { headers: { "ratelimit-limit": "10", "ratelimit-remaining": "9", "ratelimit-reset": "3" } });
    });
    expect((await api.delete("/api/v1/x")).data).toBeUndefined();
    expect((await api.put("/api/v1/x", { a: 1 })).data).toBe("plain");
    expect((await api.post("/api/v1/x")).rateLimit).toEqual({ limit: 10, remaining: 9, resetSeconds: 3 });
    expect(apiCalls(calls)[2]!.init.body).toBeUndefined();
  });

  it("only accepts relative same-host paths", async () => {
    const { api } = setup(() => token());
    for (const p of ["https://evil.example/x", "//evil.example/x", "api/v1/x", "javascript:alert(1)"]) {
      const e = (await api.get(p).then(fail, (x: unknown) => x)) as Error;
      expect(e.message).toMatch(/path must/);
    }
  });

  it("throws typed RFC 9457 problems with extension members", async () => {
    const { api } = setup((url) =>
      isTok(url) ? token() : json({ type: "https://dp/problems/plan", title: "Upgrade required", status: 402, detail: "Pro only", requiredPlan: "pro", errors: [{ pointer: "/name", detail: "bad" }] }, { status: 402, type: "application/problem+json" }),
    );
    const p = (await api.post("/api/v1/projects", { name: "" }).then(fail, (x: unknown) => x)) as ApiProblemError;
    expect(p instanceof ApiProblemError).toBe(true);
    expect(p.status).toBe(402);
    expect(p.type).toBe("https://dp/problems/plan");
    expect(p.title).toBe("Upgrade required");
    expect(p.detail).toBe("Pro only");
    expect(p.errors).toEqual([{ pointer: "/name", detail: "bad" }]);
    expect(p.problem.requiredPlan).toBe("pro");
    expect(p.isRateLimited).toBe(false);
    expect(p.isPreconditionFailed).toBe(false);
    expect(p.message).toMatch(/402.*Upgrade required.*Pro only/);
  });

  it("builds a problem from non-JSON error bodies and flags 412", async () => {
    const { api } = setup((url) => (isTok(url) ? token() : new Response("oops", { status: 412, statusText: "Precondition Failed" })));
    const e = (await api.put("/api/v1/x", {}, { ifMatch: '"old"' }).catch((x: unknown) => x)) as ApiProblemError;
    expect(e.isPreconditionFailed).toBe(true);
    expect(e.problem).toEqual({ status: 412, title: "Precondition Failed" });
    const { api: api2 } = setup((url) => (isTok(url) ? token() : new Response("[1]", { status: 500 })));
    const e2 = (await api2.get("/api/v1/x").catch((x: unknown) => x)) as ApiProblemError;
    expect(e2.problem).toEqual({ status: 500, title: "HTTP 500" });
  });

  it("gives up after a second 401", async () => {
    let n = 0;
    const { api } = setup((url) => (isTok(url) ? token(++n) : json({ title: "Unauthorized" }, { status: 401 })));
    const e = (await api.get("/api/v1/x").catch((x: unknown) => x)) as ApiProblemError;
    expect(e.status).toBe(401);
    expect(n).toBe(2);
  });
});

describe("api client: retries", () => {
  it("retries 429 honoring Retry-After seconds and dates, capped", async () => {
    let n = 0;
    const { api, sleeps } = setup((url) => {
      if (isTok(url)) return token();
      n++;
      if (n === 1) return json({ title: "Too many" }, { status: 429, headers: { "retry-after": "2" } });
      if (n === 2) return json({ title: "Too many" }, { status: 429, headers: { "retry-after": new Date(1_000_000 + 5000).toUTCString() } });
      if (n === 3) return json({ title: "Too many" }, { status: 429, headers: { "retry-after": "9999" } });
      return json({ ok: 1 });
    });
    expect((await api.post("/api/v1/x", {})).data).toEqual({ ok: 1 });
    expect(sleeps).toEqual([2000, 5000, 30_000]);
  });

  it("backs off exponentially with jitter without Retry-After and then throws with retryAfter", async () => {
    const { api, sleeps } = setup((url) => (isTok(url) ? token() : json({ title: "busy" }, { status: 503 })), { random: () => 0 });
    const e = (await api.get("/api/v1/x").catch((x: unknown) => x)) as ApiProblemError;
    expect(e.status).toBe(503);
    expect(sleeps).toEqual([250, 500, 1000]);
    const { api: api2, sleeps: s2 } = setup((url) => (isTok(url) ? token() : json({ title: "x" }, { status: 429, headers: { "retry-after": "7" } })), { maxRetries: 1 });
    const e2 = (await api2.get("/api/v1/x").catch((x: unknown) => x)) as ApiProblemError;
    expect(e2.retryAfter).toBe(7);
    expect(e2.isRateLimited).toBe(true);
    expect(s2).toEqual([7000]);
  });

  it("does not retry 503 on POST/PATCH, and ignores junk Retry-After", async () => {
    const { api, sleeps } = setup((url) => (isTok(url) ? token() : json({}, { status: 503 })));
    await api.post("/api/v1/x", {}).catch(() => {});
    await api.patch("/api/v1/x", {}).catch(() => {});
    expect(sleeps).toEqual([]);
    expect(parseRetryAfter("soon")).toBeUndefined();
    expect(parseRetryAfter(null)).toBeUndefined();
    expect(parseRetryAfter(new Date(0).toUTCString(), 10_000)).toBe(0);
  });
});

describe("api client: pagination", () => {
  const page = (items: number[], next?: string) => json({ items, nextCursor: next ? "c" : null }, { headers: next ? { link: `<${next}>; rel="next"` } : {} });

  it("iterates items across pages via Link rel=next", async () => {
    const { api, calls } = setup((url) => {
      if (isTok(url)) return token();
      if (url.includes("cursor=2")) return page([3]);
      if (url.includes("cursor=1")) return page([2], "/api/v1/things?limit=1&cursor=2");
      return page([1], "https://dp.example.com/api/v1/things?limit=1&cursor=1");
    });
    const seen: number[] = [];
    for await (const n of api.paginate<number>("/api/v1/things", { query: { limit: 1 } })) seen.push(n);
    expect(seen).toEqual([1, 2, 3]);
    expect(apiCalls(calls).map((c) => c.url)).toEqual([
      "https://dp.example.com/api/v1/things?limit=1",
      "https://dp.example.com/api/v1/things?limit=1&cursor=1",
      "https://dp.example.com/api/v1/things?limit=1&cursor=2",
    ]);
    const pages: number[] = [];
    for await (const p of api.pages<number>("/api/v1/things")) pages.push(p.data.items.length);
    expect(pages).toEqual([1, 1, 1]);
  });

  it("never follows a Link to another origin (no token leak)", async () => {
    const { api, calls } = setup((url) => (isTok(url) ? token() : page([1], "https://evil.example/steal")));
    const seen: number[] = [];
    for await (const n of api.paginate<number>("/api/v1/things")) seen.push(n);
    expect(seen).toEqual([1]);
    expect(calls.some((c) => c.url.includes("evil"))).toBe(false);
  });

  it("tolerates a missing items array and malformed links", async () => {
    const { api } = setup((url) => (isTok(url) ? token() : json({}, { headers: { link: "<http://[bad>; rel=next" } })));
    const seen: unknown[] = [];
    for await (const n of api.paginate("/api/v1/things")) seen.push(n);
    expect(seen).toEqual([]);
  });

  it("parses Link headers", () => {
    expect(parseNextLink(null)).toBeNull();
    expect(parseNextLink('</a>; rel="prev", </b>; rel="next"')).toBe("/b");
    expect(parseNextLink("</c>; rel=next; title=x")).toBe("/c");
    expect(parseNextLink('</d>; rel="last next"')).toBe("/d");
    expect(parseNextLink('</e>; rel="last"')).toBeNull();
    expect(parseNextLink("</f>")).toBeNull();
  });
});

describe("api client: timeouts", () => {
  it("passes an abort signal and can be disabled", async () => {
    const { api, calls } = setup((url) => (isTok(url) ? token() : json({})));
    const ac = new AbortController();
    await api.get("/api/v1/x", { signal: ac.signal });
    expect(apiCalls(calls)[0]!.init.signal instanceof AbortSignal).toBe(true);
    const none = setup((url) => (isTok(url) ? token() : json({})), { timeoutMs: 0 });
    await none.api.get("/api/v1/x");
    expect(apiCalls(none.calls)[0]!.init.signal).toBeUndefined();
    await none.api.get("/api/v1/x", { signal: ac.signal });
    expect(apiCalls(none.calls)[1]!.init.signal).toBe(ac.signal);
  });
});

describe("api client: hardening", () => {
  it("rejects dot segments so interpolated ids cannot traverse to another endpoint", async () => {
    const { api, calls } = setup((url) => (isTok(url) ? token() : json({})));
    for (const p of ["/api/v1/projects/../oauth/token", "/api/v1/projects/%2e%2E/x", "/api/v1/./x", "/api/v1/.%2e/x", "/api/v1/a\\..\\b", "/api/v1/.\t./x", `/api/v1/projects/${encodeURIComponent("..")}/deploys`]) {
      let err: Error | undefined;
      try {
        await api.get(p);
      } catch (e) {
        err = e as Error;
      }
      expect(err?.message ?? "").toMatch(/\. or \.\. segments/);
    }
    expect(calls).toHaveLength(0);
    await api.get("/api/v1/flags/a..b/x.y", { query: { q: "../.." } });
    expect(apiCalls(calls)[0]!.url).toBe("https://dp.example.com/api/v1/flags/a..b/x.y?q=..%2F..");
    await api.get("/api/v1/x?next=/../y");
    expect(apiCalls(calls)[1]!.url).toBe("https://dp.example.com/api/v1/x?next=/../y");
  });

  it("never follows redirects from the token endpoint and keeps the access token out of inspect output", async () => {
    const { api, calls } = setup((url) => (isTok(url) ? token(7) : json({})));
    await api.get("/api/v1/x");
    const tok = calls.find((c) => isTok(c.url))!;
    expect(tok.init.redirect).toBe("error");
    const { inspect } = await import("node:util");
    expect(inspect(api, { depth: 5 })).not.toMatch(/tok7|s3cret/);
    expect(JSON.stringify(api)).not.toMatch(/tok7|s3cret/);
  });
});
