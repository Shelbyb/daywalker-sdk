import { describe, it, beforeEach, afterEach } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runOnboard, STATE_FILE, type OnboardDeps } from "../src/onboard/index.ts";
import { collectHookEnv, validateHook } from "../src/onboard/hooks.ts";
import { createApi, OnboardApiError, type OnboardApi } from "../src/onboard/api.ts";
import type { Prompter } from "../src/onboard/prompts.ts";
import { buildAllowedOrigins, extractToken, normalizeAppUrl, validatePassword } from "../src/onboard/steps.ts";

const SERVICES = [
  { id: "svc_1", slug: "gigpulse", name: "GigPulse", status: "LIVE" },
  { id: "svc_2", slug: "sonalyze", name: "Sonalyze", status: "LIVE" },
];
const PASSWORD = "Str0ng!Passw0rd#1";

let dir: string;
let calls: { path: string; method?: string; body?: any }[];
let order: string[];
let envStore: Map<string, string>;
let inits: Record<string, string | boolean>[];
let logs: string[];

function fakeApi(overrides: Record<string, () => unknown> = {}): OnboardApi {
  return (async (p: string, init: { method?: string; body?: any; token?: string } = {}) => {
    calls.push({ path: p, method: init.method, body: init.body });
    order.push(p);
    if (overrides[p]) return overrides[p]();
    if (p === "/api/v1/auth/signup") return { ok: true };
    if (p === "/api/v1/auth/verify-email") return { ok: true };
    if (p === "/api/v1/auth/login") return { token: "session_abc" };
    if (p === "/api/v1/services") return { services: SERVICES };
    if (p === "/api/v1/tokens") return { rawSecret: "srv_live_secret" };
    throw new Error(`unexpected ${p}`);
  }) as OnboardApi;
}

function fakeDeps(): OnboardDeps {
  return {
    async init(opts) {
      inits.push(opts);
      envStore.set("DAYWALKER_KEY_ID", "kid_1");
    },
    readEnvFile: () => new Map(envStore),
    writeEnvFile(_file, values) {
      for (const [k, v] of Object.entries(values)) {
        if (/["'`$\\\u0000-\u001f]/.test(v ?? "")) throw new Error(`unsafe ${k}`);
        if (v === null) envStore.delete(k);
        else envStore.set(k, v);
      }
    },
    ensureGitignored() {},
  };
}

/** Answers prompts by matching the question text; records every question asked. */
function fakePrompter(answers: Array<[RegExp, string | boolean]>): Prompter & { asked: string[] } {
  const asked: string[] = [];
  const find = (q: string) => {
    asked.push(q);
    const hit = answers.find(([re]) => re.test(q));
    if (!hit) throw new Error(`unanswered prompt: ${q}`);
    return hit[1];
  };
  return {
    asked,
    ask: async (q, fallback = "") => String(find(q)) || fallback,
    hidden: async (q) => String(find(q)),
    confirm: async (q) => Boolean(find(q)),
    close() {},
  };
}

const baseAnswers: Array<[RegExp, string | boolean]> = [
  [/Your name/, "Ada"],
  [/Email address/, "ada@example.com"],
  [/already have a Daywalker account/, false],
  [/Confirm password/, PASSWORD],
  [/Daywalker password/, PASSWORD],
  [/verification link/, "https://auth.daywalker.dev/verify-email?token=tok_123"],
  [/Which service/, "2"],
  [/Public app URL/, "https://sonalyze.example.com/some/path"],
];

function run(opts: Record<string, string | boolean>, prompter: Prompter | null, api: OnboardApi = fakeApi(), env: NodeJS.ProcessEnv = {}) {
  return runOnboard(opts, fakeDeps(), { cwd: dir, api, prompter, env, log: (m) => logs.push(m) });
}

beforeEach(() => {
  dir = fs.mkdtempSync(path.join(os.tmpdir(), "dw-onboard-"));
  calls = [];
  order = [];
  envStore = new Map();
  inits = [];
  logs = [];
});

afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

describe("onboard flow", () => {
  it("signs up, verifies, logs in, picks a service from the menu, asks the domain after, and registers the key", async () => {
    const prompter = fakePrompter(baseAnswers);
    const result = await run({}, prompter);
    assert.strictEqual(result.exitCode, 0);

    assert.deepStrictEqual(order, ["/api/v1/auth/signup", "/api/v1/auth/verify-email", "/api/v1/auth/login", "/api/v1/services", "/api/v1/tokens"]);
    assert.strictEqual(calls[0].body.serviceSlug, undefined);
    assert.deepStrictEqual(calls[1].body, { token: "tok_123" });

    const serviceAsk = prompter.asked.findIndex((q) => /Which service/.test(q));
    const domainAsk = prompter.asked.findIndex((q) => /Public app URL/.test(q));
    assert.ok(serviceAsk >= 0 && domainAsk > serviceAsk, "domain must be asked after the service");

    const tokenBody = calls.find((c) => c.path === "/api/v1/tokens")!.body;
    assert.strictEqual(tokenBody.serviceId, "svc_2");
    assert.deepStrictEqual(tokenBody.allowedOrigins, ["https://localhost:3000", "https://sonalyze.example.com"]);

    assert.strictEqual(envStore.get("DAYWALKER_API_KEY"), "srv_live_secret");
    assert.deepStrictEqual(inits, [{ service: "sonalyze", domain: "sonalyze.example.com" }]);
    assert.ok(!fs.existsSync(path.join(dir, STATE_FILE)), "state file removed when finished");
    assert.ok(!logs.join("\n").includes("srv_live_secret"), "token is never logged");
  });

  it("--service skips the menu and is sent with signup; --url skips the domain prompt", async () => {
    const prompter = fakePrompter(baseAnswers.filter(([re]) => !/Which service|Public app URL/.test(String(re))));
    const result = await run({ service: "gigpulse", url: "https://gig.example.com" }, prompter);
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(calls[0].body.serviceSlug, "gigpulse");
    assert.strictEqual(calls.find((c) => c.path === "/api/v1/tokens")!.body.serviceId, "svc_1");
    assert.ok(!prompter.asked.some((q) => /Which service/.test(q)));
  });

  it("stops before login when verification is skipped, and saves state without secrets", async () => {
    const prompter = fakePrompter(baseAnswers.map(([re, v]) => (/verification link/.test(String(re)) ? [re, ""] : [re, v]) as [RegExp, string | boolean]));
    const result = await run({}, prompter);
    assert.strictEqual(result.exitCode, 2);
    assert.deepStrictEqual(order, ["/api/v1/auth/signup"]);
    const saved = fs.readFileSync(path.join(dir, STATE_FILE), "utf8");
    assert.strictEqual(JSON.parse(saved).stage, "signed_up");
    assert.ok(!saved.includes(PASSWORD));
  });

  it("resumes from saved state without signing up again", async () => {
    fs.writeFileSync(path.join(dir, STATE_FILE), JSON.stringify({ stage: "signed_up", name: "Ada", email: "ada@example.com" }));
    const prompter = fakePrompter(baseAnswers);
    const result = await run({}, prompter);
    assert.strictEqual(result.exitCode, 0);
    assert.ok(!order.includes("/api/v1/auth/signup"));
    assert.strictEqual(order[0], "/api/v1/auth/verify-email");
  });

  it("keeps an existing DAYWALKER_API_KEY unless confirmed", async () => {
    envStore.set("DAYWALKER_API_KEY", "old_key");
    const prompter = fakePrompter([...baseAnswers, [/already exists/, false]]);
    const result = await run({}, prompter);
    assert.strictEqual(result.exitCode, 1);
    assert.ok(!order.includes("/api/v1/tokens"));
    assert.strictEqual(envStore.get("DAYWALKER_API_KEY"), "old_key");
  });

  it("fails with the server message when the service is not visible", async () => {
    const result = await run({ service: "nope", url: "https://x.example.com" }, fakePrompter(baseAnswers));
    assert.strictEqual(result.exitCode, 1);
    assert.ok(!order.includes("/api/v1/tokens"));
    assert.strictEqual(envStore.size, 0);
  });

  it("refuses MFA accounts", async () => {
    const api = fakeApi({ "/api/v1/auth/login": () => ({ mfaRequired: true }) });
    const result = await run({}, fakePrompter(baseAnswers), api);
    assert.strictEqual(result.exitCode, 1);
    assert.ok(!order.includes("/api/v1/tokens"));
  });

  it("surfaces API errors without partial writes", async () => {
    const api = fakeApi({
      "/api/v1/tokens": () => {
        throw new OnboardApiError(429, "Rate limited: slow down");
      },
    });
    const result = await run({}, fakePrompter(baseAnswers), api);
    assert.strictEqual(result.exitCode, 1);
    assert.strictEqual(envStore.has("DAYWALKER_API_KEY"), false);
    assert.strictEqual(inits.length, 0);
  });

  it("--dry-run makes no network calls and writes nothing", async () => {
    const result = await run({ "dry-run": true, name: "Ada", email: "ada@example.com" }, null);
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(calls.length, 0);
    assert.deepStrictEqual(fs.readdirSync(dir), []);
  });

  it("runs non-interactively from flags and the environment", async () => {
    const env = { DAYWALKER_ONBOARD_PASSWORD: PASSWORD, DAYWALKER_ONBOARD_VERIFY_TOKEN: "tok_env" };
    const result = await run({ yes: true, name: "Ada", email: "ada@example.com", service: "sonalyze", url: "app.example.com" }, null, fakeApi(), env);
    assert.strictEqual(result.exitCode, 0);
    assert.deepStrictEqual(calls[1].body, { token: "tok_env" });
    assert.strictEqual(calls.find((c) => c.path === "/api/v1/tokens")!.body.allowedOrigins[1], "https://app.example.com");
  });

  it("registers the key against the same --auth-url the token was created on", async () => {
    const env = { DAYWALKER_ONBOARD_PASSWORD: PASSWORD, DAYWALKER_ONBOARD_VERIFY_TOKEN: "tok_env" };
    const opts = { yes: true, name: "Ada", email: "ada@example.com", service: "sonalyze", url: "app.example.com", "auth-url": "https://staging.auth.example.com" };
    const result = await run(opts, null, fakeApi(), env);
    assert.strictEqual(result.exitCode, 0);
    assert.deepStrictEqual(inits, [{ service: "sonalyze", domain: "app.example.com", "auth-url": "https://staging.auth.example.com" }]);
  });

  it("refuses a non-https auth URL before sending the password anywhere", async () => {
    const env = { DAYWALKER_ONBOARD_PASSWORD: PASSWORD, DAYWALKER_ONBOARD_VERIFY_TOKEN: "t" };
    const opts = { yes: true, name: "Ada", email: "ada@example.com", service: "sonalyze", url: "app.example.com", "auth-url": "http://auth.example.com" };
    const result = await runOnboard(opts, fakeDeps(), { cwd: dir, prompter: null, env, log: (m) => logs.push(m) });
    assert.strictEqual(result.exitCode, 1);
    assert.strictEqual(envStore.size, 0);
  });

  it("does not write the state file through a symlink", { skip: process.platform === "win32" }, async () => {
    const target = path.join(dir, "elsewhere.txt");
    fs.writeFileSync(target, "keep\n");
    fs.symlinkSync(target, path.join(dir, STATE_FILE));
    const prompter = fakePrompter(baseAnswers);
    const result = await run({}, prompter);
    assert.strictEqual(result.exitCode, 1);
    assert.strictEqual(fs.readFileSync(target, "utf8"), "keep\n");
  });

  it("ignores services with malformed slugs from the server", async () => {
    const api = fakeApi({ "/api/v1/services": () => ({ services: [{ id: "svc_x", slug: "bad\u001b[2Jslug" }, ...SERVICES] }) });
    const prompter = fakePrompter(baseAnswers.map(([re, v]) => (/Which service/.test(String(re)) ? [re, "1"] : [re, v]) as [RegExp, string | boolean]));
    const result = await run({}, prompter, api);
    assert.strictEqual(result.exitCode, 0);
    assert.strictEqual(calls.find((c) => c.path === "/api/v1/tokens")!.body.serviceId, SERVICES[0].id);
    assert.ok(!logs.join("\n").includes("\u001b"));
  });
});

describe("onboard API client", () => {
  it("refuses insecure base URLs", () => {
    for (const bad of ["http://auth.example.com", "https://u:p@auth.example.com", "nope"]) {
      assert.throws(() => createApi({ baseUrl: bad }), /DAYWALKER_AUTH_URL/, bad);
    }
    assert.doesNotThrow(() => createApi({ baseUrl: "http://127.0.0.1:8787" }));
  });

  it("refuses redirects and times out every attempt", async (t) => {
    const keepAlive = setInterval(() => {}, 1000); // AbortSignal.timeout timers are unref'd
    t.after(() => clearInterval(keepAlive));
    const seen: RequestInit[] = [];
    const fetchImpl = (async (_url: string, init: RequestInit) => {
      seen.push(init);
      return new Promise((_resolve, reject) => init.signal!.addEventListener("abort", () => reject(init.signal!.reason)));
    }) as unknown as typeof fetch;
    const api = createApi({ baseUrl: "https://auth.example.com", fetchImpl, retries: 0, timeoutMs: 20 });
    await assert.rejects(api("/api/v1/auth/login", { method: "POST", body: { email: "a", password: "b" } }), /Network error/);
    assert.strictEqual(seen[0].redirect, "error");
    assert.ok(seen[0].signal);
  });
});

describe("project hook", () => {
  const HOOK = `export default {
  defaultService: 'sonalyze',
  localOrigins: ['https://localhost:4000'],
  env: [
    { key: 'SPOTIFY_CLIENT_ID', label: 'Spotify Client ID', required: true },
    { key: 'LASTFM_API_KEY', label: 'Last.fm key', mirrorTo: ['NEXT_PUBLIC_LASTFM_API_KEY'] },
  ],
  generate: { NEXTAUTH_SECRET: 'base64-48' },
  fixed: { NEXTAUTH_URL: 'https://localhost:4000' },
  nextSteps: (ctx) => ['Add redirect URI for ' + ctx.domain],
};
`;

  it("applies prompts, generated, fixed and mirrored values, local origins, default service and next steps", async () => {
    fs.writeFileSync(path.join(dir, "daywalker.onboard.mjs"), HOOK);
    envStore.set("NEXTAUTH_URL", "https://keep.example.com");
    const prompter = fakePrompter([
      ...baseAnswers.filter(([re]) => !/Which service/.test(String(re))),
      [/Run project setup/, true],
      [/NEXTAUTH_URL is already set/, false],
      [/Spotify Client ID/, "spot_id"],
      [/Last\.fm key/, "lfm"],
    ]);
    const result = await run({ url: "https://sonalyze.example.com" }, prompter);
    assert.strictEqual(result.exitCode, 0);

    assert.strictEqual(calls.find((c) => c.path === "/api/v1/auth/signup")!.body.serviceSlug, "sonalyze");
    assert.deepStrictEqual(calls.find((c) => c.path === "/api/v1/tokens")!.body.allowedOrigins, ["https://localhost:4000", "https://sonalyze.example.com"]);
    assert.strictEqual(envStore.get("SPOTIFY_CLIENT_ID"), "spot_id");
    assert.strictEqual(envStore.get("LASTFM_API_KEY"), "lfm");
    assert.strictEqual(envStore.get("NEXT_PUBLIC_LASTFM_API_KEY"), "lfm");
    assert.ok((envStore.get("NEXTAUTH_SECRET") ?? "").length >= 60);
    assert.strictEqual(envStore.get("NEXTAUTH_URL"), "https://keep.example.com", "existing value kept without confirmation");
    assert.ok(logs.some((l) => l.includes("Add redirect URI for sonalyze.example.com")));
  });

  it("does not run the hook when the user declines", async () => {
    fs.writeFileSync(path.join(dir, "daywalker.onboard.mjs"), `throw new Error("must not run");`);
    const prompter = fakePrompter([...baseAnswers, [/Run project setup/, false]]);
    const result = await run({}, prompter);
    assert.strictEqual(result.exitCode, 0);
    assert.ok(!envStore.has("NEXTAUTH_SECRET"));
  });

  it("fails cleanly when the hook throws", async () => {
    fs.writeFileSync(path.join(dir, "daywalker.onboard.mjs"), `throw new Error("boom");`);
    const result = await run({ yes: true, name: "Ada", email: "ada@example.com", service: "sonalyze", url: "https://a.example.com" }, null, fakeApi(), {
      DAYWALKER_ONBOARD_PASSWORD: PASSWORD,
      DAYWALKER_ONBOARD_VERIFY_TOKEN: "t",
    });
    assert.strictEqual(result.exitCode, 1);
    assert.strictEqual(calls.length, 0);
  });

  it("rejects bad config", () => {
    assert.throws(() => validateHook({ env: [{ key: "DAYWALKER_API_KEY" }] }), /managed by the SDK/);
    assert.throws(() => validateHook({ env: [{ key: "lower" }] }), /invalid env key/);
    assert.throws(() => validateHook({ generate: { X: "md5" } }), /must be one of/);
    assert.throws(() => validateHook({ localOrigins: ["http://evil.example.com"] }), /localOrigins/);
    assert.throws(() => validateHook({ fixed: { A: 'x"y' } }), /refusing/);
    assert.throws(() => validateHook(null), /default-export an object/);
  });

  it("rejects unsafe values entered at a prompt", async () => {
    const config = validateHook({ env: [{ key: "MY_SECRET" }] });
    const prompter = fakePrompter([[/MY_SECRET/, "a$b"]]);
    await assert.rejects(
      collectHookEnv(config, { existing: new Map(), prompter, env: {}, log() {}, replaceExisting: false }),
      /refusing to write/
    );
  });
});

describe("onboard helpers", () => {
  it("normalizes app URLs to public https origins", () => {
    assert.strictEqual(normalizeAppUrl("app.example.com/x"), "https://app.example.com");
    assert.strictEqual(normalizeAppUrl("http://app.example.com"), null);
    assert.strictEqual(normalizeAppUrl("https://localhost:3000"), null);
    assert.strictEqual(normalizeAppUrl(""), null);
  });

  it("builds deduplicated allowed origins", () => {
    assert.deepStrictEqual(buildAllowedOrigins("https://localhost:3000"), ["https://localhost:3000"]);
    assert.deepStrictEqual(buildAllowedOrigins("https://a.example.com", ["https://localhost:3000"]), ["https://localhost:3000", "https://a.example.com"]);
  });

  it("enforces the password rule", () => {
    assert.ok(validatePassword("short"));
    assert.ok(validatePassword("alllowercaseletters"));
    assert.strictEqual(validatePassword(PASSWORD), null);
  });

  it("extracts tokens from links or raw values", () => {
    assert.strictEqual(extractToken("https://x.dev/verify-email?token=abc"), "abc");
    assert.strictEqual(extractToken("abc123"), "abc123");
    assert.strictEqual(extractToken("  "), null);
  });
});
