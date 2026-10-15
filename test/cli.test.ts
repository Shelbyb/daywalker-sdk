import { describe, it, before, after } from "node:test";
import assert from "node:assert";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const CLI = fileURLToPath(new URL("../src/cli.ts", import.meta.url));
const TSX = import.meta.resolve("tsx");
const posixOnly = { skip: process.platform === "win32" };

interface RunResult {
  status: number | null;
  stdout: string;
  stderr: string;
}

/** Runs the CLI from source (no build needed) without inheriting any DAYWALKER_* settings. */
function run(cwd: string, args: string[], opts: { env?: Record<string, string>; stdin?: string } = {}): Promise<RunResult> {
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith("DAYWALKER_") && v !== undefined) env[k] = v;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", TSX, CLI, ...args], { cwd, env: { ...env, ...opts.env } });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    child.on("error", reject);
    child.on("close", (status) => resolve({ status, stdout, stderr }));
    child.stdin.end(opts.stdin ?? "");
  });
}

function tmpdir() {
  return fs.mkdtempSync(path.join(os.tmpdir(), "daywalker-cli-test-"));
}

function readEnv(dir: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of fs.readFileSync(path.join(dir, ".env.local"), "utf8").split("\n")) {
    const m = line.match(/^([A-Z0-9_]+)="(.*)"$/);
    if (m) out[m[1]] = m[2];
  }
  return out;
}

// A fake Daywalker Auth: POST /api/v1/keys/register answers with `registerStatus`.
let registerStatus = 201;
const registrations: Array<{ auth: string | undefined; body: any }> = [];
let server: http.Server;
let authUrl = "";

before(async () => {
  server = http.createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      registrations.push({ auth: req.headers.authorization, body: body ? JSON.parse(body) : null });
      res.writeHead(registerStatus, { "content-type": "application/json" });
      res.end(JSON.stringify(registerStatus < 300 ? { ok: true } : { error: "registration rejected" }));
    });
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  authUrl = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});

after(() => server.close());

async function initDir(): Promise<{ dir: string; key: string }> {
  const dir = tmpdir();
  const res = await run(dir, ["init", "--service", "svc", "--domain", "svc.example.com", "--auth-url", authUrl, "--skip-register"]);
  assert.strictEqual(res.status, 0, res.stderr);
  return { dir, key: readEnv(dir).DAYWALKER_SIGNING_KEY };
}

describe("CLI rotate", () => {
  it("writes nothing and exits non-zero when registration fails", async () => {
    const { dir, key } = await initDir();
    const before = fs.readFileSync(path.join(dir, ".env.local"), "utf8");
    try {
      registerStatus = 500;
      const res = await run(dir, ["rotate"], { env: { DAYWALKER_API_KEY: "srv_live_rotate" } });
      assert.notStrictEqual(res.status, 0);
      assert.match(res.stderr, /registration failed/i);
      assert.strictEqual(fs.readFileSync(path.join(dir, ".env.local"), "utf8"), before);
      assert.strictEqual(readEnv(dir).DAYWALKER_SIGNING_KEY, key);
    } finally {
      registerStatus = 201;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to rotate without an API key unless --skip-register is given", async () => {
    const { dir, key } = await initDir();
    try {
      const res = await run(dir, ["rotate"]);
      assert.notStrictEqual(res.status, 0);
      assert.strictEqual(readEnv(dir).DAYWALKER_SIGNING_KEY, key);

      const skipped = await run(dir, ["rotate", "--no-register"]);
      assert.strictEqual(skipped.status, 0, skipped.stderr);
      const env = readEnv(dir);
      assert.notStrictEqual(env.DAYWALKER_SIGNING_KEY, key);
      assert.strictEqual(env.DAYWALKER_SIGNING_KEY_PREVIOUS, key);
      assert.match(fs.readFileSync(path.join(dir, ".env.local"), "utf8"), /# Previous signing key, kept for rollback/);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("writes the new key and keeps the old one after successful registration", async () => {
    const { dir, key } = await initDir();
    try {
      registrations.length = 0;
      const res = await run(dir, ["rotate"], { env: { DAYWALKER_API_KEY: "srv_live_rotate" } });
      assert.strictEqual(res.status, 0, res.stderr);
      const env = readEnv(dir);
      assert.strictEqual(env.DAYWALKER_SIGNING_KEY_PREVIOUS, key);
      assert.strictEqual(registrations.length, 1);
      assert.strictEqual(registrations[0].auth, "Bearer srv_live_rotate");
      assert.strictEqual(registrations[0].body.keyId, env.DAYWALKER_KEY_ID);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("CLI init", () => {
  it("--force does not replace the key when registration fails, and keeps the old key on success", async () => {
    const { dir, key } = await initDir();
    const before = fs.readFileSync(path.join(dir, ".env.local"), "utf8");
    try {
      registerStatus = 403;
      const failed = await run(dir, ["init", "--force"], { env: { DAYWALKER_API_KEY: "srv_live_init" } });
      assert.notStrictEqual(failed.status, 0);
      assert.strictEqual(fs.readFileSync(path.join(dir, ".env.local"), "utf8"), before);

      const noKey = await run(dir, ["init", "--force"]);
      assert.notStrictEqual(noKey.status, 0);
      assert.strictEqual(fs.readFileSync(path.join(dir, ".env.local"), "utf8"), before);

      registerStatus = 201;
      const ok = await run(dir, ["init", "--force"], { env: { DAYWALKER_API_KEY: "srv_live_init" } });
      assert.strictEqual(ok.status, 0, ok.stderr);
      const env = readEnv(dir);
      assert.notStrictEqual(env.DAYWALKER_SIGNING_KEY, key);
      assert.strictEqual(env.DAYWALKER_SIGNING_KEY_PREVIOUS, key);
    } finally {
      registerStatus = 201;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("exits non-zero and writes nothing when registration of a new key fails", async () => {
    const dir = tmpdir();
    try {
      registerStatus = 500;
      const res = await run(dir, ["init", "--service", "svc", "--domain", "svc.example.com", "--auth-url", authUrl], {
        env: { DAYWALKER_API_KEY: "srv_live_init" },
      });
      assert.notStrictEqual(res.status, 0);
      assert.strictEqual(fs.existsSync(path.join(dir, ".env.local")), false);
    } finally {
      registerStatus = 201;
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("reads the API key from stdin with --api-key-stdin", async () => {
    const dir = tmpdir();
    try {
      registrations.length = 0;
      const res = await run(dir, ["init", "--service", "svc", "--domain", "svc.example.com", "--auth-url", authUrl, "--api-key-stdin"], {
        stdin: "srv_live_from_stdin\n",
      });
      assert.strictEqual(res.status, 0, res.stderr);
      assert.doesNotMatch(res.stderr, /--api-key exposes/);
      assert.strictEqual(registrations[0]?.auth, "Bearer srv_live_from_stdin");
      assert.strictEqual(readEnv(dir).DAYWALKER_API_KEY, "srv_live_from_stdin");

      const empty = await run(dir, ["init", "--api-key-stdin"], { stdin: "" });
      assert.notStrictEqual(empty.status, 0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("--json still prints the private key for secret stores, with a warning on stderr", async () => {
    const dir = tmpdir();
    try {
      const res = await run(dir, ["init", "--service", "svc", "--json", "--skip-register"]);
      assert.strictEqual(res.status, 0, res.stderr);
      assert.ok(JSON.parse(res.stdout).DAYWALKER_SIGNING_KEY);
      assert.match(res.stderr, /includes the private signing key/);
      assert.strictEqual(fs.existsSync(path.join(dir, ".env.local")), false);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("CLI .env.local writing", () => {
  it("rejects values that could inject lines or be expanded", async () => {
    const dir = tmpdir();
    try {
      for (const bad of [`https://a.example/"\nEVIL=1`, "https://a.example/$HOME", "https://a.example/\\x", `https://a.example/"`]) {
        const res = await run(dir, ["init", "--service", "svc", "--skip-register", "--auth-url", bad]);
        assert.notStrictEqual(res.status, 0, bad);
        assert.strictEqual(fs.existsSync(path.join(dir, ".env.local")), false, bad);
      }
      const apiKey = await run(dir, ["init", "--service", "svc", "--skip-register"], { env: { DAYWALKER_API_KEY: 'k"\nX=1' } });
      assert.notStrictEqual(apiKey.status, 0);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("replaces an existing 0644 file atomically with a 0600 one and keeps other lines", posixOnly, async () => {
    const dir = tmpdir();
    try {
      const envFile = path.join(dir, ".env.local");
      fs.writeFileSync(envFile, "OTHER=1\n", { mode: 0o644 });
      fs.chmodSync(envFile, 0o644);
      const inode = fs.statSync(envFile).ino;
      const res = await run(dir, ["init", "--service", "svc", "--skip-register"]);
      assert.strictEqual(res.status, 0, res.stderr);
      const st = fs.statSync(envFile);
      assert.strictEqual(st.mode & 0o777, 0o600);
      assert.notStrictEqual(st.ino, inode);
      assert.match(fs.readFileSync(envFile, "utf8"), /^OTHER=1\n/);
      assert.deepStrictEqual(fs.readdirSync(dir).filter((f) => f.endsWith(".tmp")), []);
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  it("refuses to write through a symlinked .env.local", posixOnly, async () => {
    const dir = tmpdir();
    try {
      const target = path.join(dir, "elsewhere.txt");
      fs.writeFileSync(target, "PUBLIC=1\n", { mode: 0o644 });
      fs.symlinkSync(target, path.join(dir, ".env.local"));
      const res = await run(dir, ["init", "--service", "svc", "--skip-register"]);
      assert.notStrictEqual(res.status, 0);
      assert.match(res.stderr, /symlink/);
      assert.strictEqual(fs.readFileSync(target, "utf8"), "PUBLIC=1\n");
      assert.ok(fs.lstatSync(path.join(dir, ".env.local")).isSymbolicLink());
    } finally {
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
