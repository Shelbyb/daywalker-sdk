#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { createDaywalker } from "./client.js";
import { parseServiceSlugs, publicHostname } from "./config.js";
import { runOnboard } from "./onboard/index.js";
import { applyLicense, checkLicense, formatReport } from "./license/index.js";
import { generateSigningKey, keySlotFor, listSigningKeys, loadSigningKey, registerPublicKey, redactSecrets, revokeSigningKey, type KeyApiResult } from "./crypto/index.js";

const HELP = `daywalker: connect a service to Daywalker Auth (RFC 9421 / Push Architecture)

Usage:
  daywalker onboard [--service <slug>] [--url <https://app>] [--name <name>] [--email <email>] [--existing-account] [--dry-run] [--yes]
  daywalker init   [--service <slug[,slug…]>] [--api-key-stdin] [--domain <host>] [--auth-url <url>] [--force] [--skip-register] [--json|--export] [--print-key]
  daywalker rotate [--service <slug[,slug…]>] [--api-key-stdin] [--domain <host>] [--auth-url <url>] [--skip-register] [--json|--export] [--print-key]
  daywalker check  [--offline]
  daywalker keys   [--domain <host>] [--auth-url <url>] [--api-key-stdin] [--json]
  daywalker revoke <keyId> [--domain <host>] [--auth-url <url>] [--api-key-stdin] [--force]
  daywalker license apply [--dir <path>] [--governing-law <text>] [--include <file,…>] [--exclude <glob,…>] [--guard-names <name,…>] [--replace-existing] [--dry-run]
  daywalker license check [--dir <path>] [--include <file,…>] [--exclude <glob,…>] [--guard-names <name,…>]

onboard  Guided setup for a new developer: sign up (or log in), verify the email, pick a service from the live
         list, give the public app URL, create an API token (allowed origins: the URL plus https://localhost:3000),
         then register a signing key (same as init). Resumable via .daywalker-onboard.json (no secrets).
         Non-interactive: --yes with DAYWALKER_ONBOARD_PASSWORD (and DAYWALKER_ONBOARD_VERIFY_TOKEN) in the env.
init     Generates an Ed25519 keypair, registers the public key directly with Daywalker Auth
         (POST /api/v1/keys/register), and writes DAYWALKER_* settings to .env.local (or outputs JSON with --json).
         Nothing is written if registration fails. --force replaces an existing key (kept as
         DAYWALKER_SIGNING_KEY_PREVIOUS for rollback). No public ingress or /.well-known route handlers are required.
rotate   Generates a new Ed25519 key, registers it with Daywalker Auth, and keeps the old one
         in .env.local as DAYWALKER_SIGNING_KEY_PREVIOUS during deployment transition. The old key stays
         registered until you revoke it (\`daywalker revoke <keyId>\`) once the new key is deployed everywhere.
         Nothing is written, and the exit code is non-zero, unless registration succeeds.
check    Validates configuration and signature readiness, then runs the OAuth client credentials grant
         against Daywalker Auth to confirm the credentials work and cover the configured service(s).
keys     Lists the signing keys registered for the domain (status, slot, expiry, last use).
revoke   Revokes a signing key now; Daywalker also ends the OAuth sessions it started. Refuses the key in
         DAYWALKER_KEY_ID (the one this service signs with) unless --force.

license  apply installs the DevPulse source-available license in a project: LICENSE, "license" in package.json (root and
         workspaces; "private" is never changed), a README section, a notice header on every file that imports this SDK or
         calls its guards, and the boot log line (added to Next.js instrumentation.ts when there is one). It only adds comments
         and metadata and is safe to re-run. check exits non-zero when anything is missing or out of date (use it in CI).
         Bundler banners, Dockerfile COPY and the governing-law clause are listed as things to do by hand or by flag.

Options:
  --api-key-stdin   Read the Daywalker API key from stdin (e.g. \`op read ... | daywalker init --api-key-stdin\`).
                    The key is otherwise taken from DAYWALKER_API_KEY in the environment or .env.local.
                    (--api-key <key> is refused: it would expose the key in shell history and process listings.)
  --offline         check only: skip the live OAuth client credentials check against Daywalker Auth.
  --skip-register   Do not register the public key (alias: --no-register); register it yourself before deploying.
  --json, --export  Output configuration as JSON for piping into Vercel, DigitalOcean, Fly.io, AWS SSM, etc.
                    The JSON includes the private key (DAYWALKER_SIGNING_KEY); nothing is written to .env.local.
  --print-key       Print the private key to stdout after writing .env.local (disabled by default for security).
`;

function args(argv: string[]) {
  const out: Record<string, string | boolean> = {};
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (!a.startsWith("--")) continue;
    const next = argv[i + 1];
    if (next && !next.startsWith("--")) {
      out[a.slice(2)] = next;
      i++;
    } else out[a.slice(2)] = true;
  }
  return out;
}

function fail(message: string): never {
  console.error(redactSecrets(`✖ ${message}`));
  process.exit(1);
}

/** Read all of stdin (for --api-key-stdin), so the key never appears in argv. */
async function readStdin(): Promise<string> {
  if (process.stdin.isTTY) fail("--api-key-stdin expects the key on stdin (pipe it in)");
  const chunks: Buffer[] = [];
  for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
  return Buffer.concat(chunks).toString("utf8").trim();
}

async function resolveApiKey(opts: Record<string, string | boolean>, existing: Map<string, string>): Promise<string | null> {
  if (opts["api-key-stdin"]) {
    const fromStdin = await readStdin();
    if (!fromStdin) fail("--api-key-stdin: no API key received on stdin");
    return fromStdin;
  }
  return String(existing.get("DAYWALKER_API_KEY") ?? process.env.DAYWALKER_API_KEY ?? "").trim() || null;
}

/** Why a key API call failed, with what to do when the domain is full. */
function keyApiFailure(what: string, result: KeyApiResult): string {
  const hint =
    result.code === "KEY_LIMIT_REACHED"
      ? "\n  The domain has 20 live keys: list them with `daywalker keys` and revoke unused ones with `daywalker revoke <keyId>`."
      : "";
  return `${what} failed (${result.status || "network"}${result.code ? ` ${result.code}` : ""}): ${result.error}${hint}`;
}

function skipRegister(opts: Record<string, string | boolean>): boolean {
  return Boolean(opts["skip-register"] || opts["no-register"]);
}

/** --json prints the private key by design (for secret stores); say so on stderr so it is never a surprise. */
function warnJsonIncludesKey(values: Record<string, string | null>) {
  if (values.DAYWALKER_SIGNING_KEY) {
    console.warn("! --json output includes the private signing key (DAYWALKER_SIGNING_KEY); pipe it straight into your secret store.");
  }
}

function readEnvFile(file: string): Map<string, string> {
  const map = new Map<string, string>();
  if (!fs.existsSync(file)) return map;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
    if (m) map.set(m[1], m[2].replace(/^"(.*)"$/, "$1"));
  }
  return map;
}

/**
 * Values are written as KEY="value". Anything a dotenv parser could interpret (quotes, `$` expansion
 * as done by Next.js / dotenv-expand, backslash escapes, newlines or other control characters) is
 * rejected instead of escaped, since parsers disagree on escaping rules.
 */
const UNSAFE_ENV_VALUE = /["'`$\\\u0000-\u001f\u007f]/;

function assertSafeEnvValues(values: Record<string, string | null>) {
  for (const [key, value] of Object.entries(values)) {
    if (value !== null && UNSAFE_ENV_VALUE.test(value)) {
      fail(`${key} contains quotes, "$", backslashes, newlines or control characters; refusing to write it to .env.local`);
    }
  }
}

function writeEnvFile(file: string, values: Record<string, string | null>, comments: Record<string, string> = {}) {
  assertSafeEnvValues(values);
  let stat: fs.Stats | null = null;
  try {
    stat = fs.lstatSync(file);
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code !== "ENOENT") throw err;
  }
  // Never follow a symlink (it could point anywhere, e.g. a world-readable file); refuse non-files.
  if (stat && stat.isSymbolicLink()) fail(`${path.basename(file)} is a symlink; refusing to write secrets through it`);
  if (stat && !stat.isFile()) fail(`${path.basename(file)} is not a regular file`);

  const lines = stat ? fs.readFileSync(file, "utf8").split("\n") : [];
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of lines) {
    const key = line.match(/^\s*([A-Z0-9_]+)\s*=/)?.[1];
    if (key && key in values) {
      seen.add(key);
      if (values[key] !== null) out.push(`${key}="${values[key]}"`);
      continue;
    }
    out.push(line);
  }
  while (out.length && out[out.length - 1] === "") out.pop();
  const added = Object.entries(values).filter(([k, v]) => !seen.has(k) && v !== null);
  if (added.length) {
    if (out.length) out.push("");
    out.push("# Daywalker Auth (managed by `daywalker init`)");
    for (const [k, v] of added) {
      if (comments[k]) out.push(`# ${comments[k]}`);
      out.push(`${k}="${v}"`);
    }
  }

  // Atomic replace: write a fresh 0600 temp file in the same directory, then rename it over the
  // target, so the secrets never sit in a file with looser permissions and readers never see a
  // half-written file.
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.${Date.now()}.tmp`);
  const fd = fs.openSync(tmp, "wx", 0o600);
  try {
    fs.fchmodSync(fd, 0o600);
    fs.writeFileSync(fd, out.join("\n") + "\n");
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  fs.closeSync(fd);
  try {
    fs.renameSync(tmp, file);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
}

const PREVIOUS_KEY_COMMENT = "Previous signing key, kept for rollback while the new key rolls out; remove it once deployed.";

function ensureGitignored(dir: string, entry: string) {
  const file = path.join(dir, ".gitignore");
  const content = fs.existsSync(file) ? fs.readFileSync(file, "utf8") : "";
  const covered = content.split("\n").some((l) => [entry, ".env*", ".env.*", ".env*.local", "*.local"].includes(l.trim()));
  if (!covered) fs.appendFileSync(file, `${content.endsWith("\n") || !content ? "" : "\n"}${entry}\n`);
}

async function init(opts: Record<string, string | boolean>) {
  const isJson = Boolean(opts.json || opts.export);
  const dir = process.cwd();
  const envFile = path.join(dir, ".env.local");
  const existing = readEnvFile(envFile);

  const slugs = parseServiceSlugs(String(opts.service ?? existing.get("DAYWALKER_SERVICE_SLUG") ?? process.env.DAYWALKER_SERVICE_SLUG ?? ""));
  // Optional: requests never name a service. Only needed to verify access tokens offline (audience check).
  if (!slugs.every((s) => /^[a-z0-9_-]+$/.test(s))) {
    fail("--service must be Daywalker service slug(s) (e.g. --service sonalyze, or gigpulse,devpulse)");
  }
  const slug = slugs.join(",");

  const rawDomain = opts.domain ? String(opts.domain) : existing.get("DAYWALKER_DOMAIN") ?? process.env.DAYWALKER_DOMAIN ?? "";
  let domain: string | null = null;
  if (rawDomain) {
    domain = publicHostname(rawDomain);
    if (!domain) fail(`--domain (${rawDomain}) is not a valid public hostname`);
  }

  const apiKey = await resolveApiKey(opts, existing);
  const authUrl = String(opts["auth-url"] ?? existing.get("DAYWALKER_AUTH_URL") ?? process.env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");

  const existingKey = existing.get("DAYWALKER_SIGNING_KEY") || null;
  const keyExists = Boolean(existingKey) && !opts.force;
  const key = keyExists ? null : await generateSigningKey();
  // --force over an existing key: keep the old one so a deployment can roll back to it.
  const previousKey = key && existingKey ? existingKey : null;

  const activeKey = key ?? (existingKey ? await loadSigningKey(existingKey) : null);
  const kid = activeKey?.publicJwk.kid ?? String(opts["key-id"] ?? "");

  // Register public key directly with Daywalker Auth if API key is provided. Replacing a key
  // requires registration: writing an unregistered key would break request signing.
  let registered = false;
  if (previousKey && !apiKey && !skipRegister(opts)) {
    fail("Replacing DAYWALKER_SIGNING_KEY requires registering the new key: set DAYWALKER_API_KEY (or use --api-key-stdin), or pass --skip-register to write it anyway");
  }
  if (apiKey && activeKey && !skipRegister(opts)) {
    if (!isJson) console.log(`• Registering public key (${activeKey.publicJwk.kid}) with Daywalker Auth...`);
    // Each key gets its own slot, so registering it never retires a key a running deployment still uses.
    const regResult = await registerPublicKey({
      authUrl,
      apiKey,
      domain,
      publicJwk: activeKey.publicJwk,
      instanceId: keySlotFor(activeKey.publicJwk.kid),
    });
    if (regResult.ok) {
      registered = true;
      if (!isJson) console.log(`✔ Public key registered with Daywalker Auth (Push Architecture)`);
    } else {
      fail(
        `${keyApiFailure("Key registration", regResult)}\n` +
          `  Nothing was written. Fix the problem and re-run, or pass --skip-register to write the key without registering it.`
      );
    }
  } else if (!apiKey && !skipRegister(opts) && !isJson) {
    console.log(`• Note: Set DAYWALKER_API_KEY in .env.local to automatically register public keys.`);
  }

  const signingKeyStr = key?.privateKeyPkcs8Base64 ?? existing.get("DAYWALKER_SIGNING_KEY") ?? "";

  const envValues: Record<string, string | null> = {
    ...(slug ? { DAYWALKER_SERVICE_SLUG: slug } : {}),
    DAYWALKER_KEY_ID: kid,
    DAYWALKER_AUTH_URL: authUrl,
    ...(domain ? { DAYWALKER_DOMAIN: domain } : {}),
    ...(apiKey ? { DAYWALKER_API_KEY: apiKey } : {}),
    ...(signingKeyStr ? { DAYWALKER_SIGNING_KEY: signingKeyStr } : {}),
    ...(previousKey ? { DAYWALKER_SIGNING_KEY_PREVIOUS: previousKey } : {}),
  };

  if (isJson) {
    warnJsonIncludesKey(envValues);
    console.log(JSON.stringify(envValues, null, 2));
    return;
  }

  writeEnvFile(envFile, envValues, { DAYWALKER_SIGNING_KEY_PREVIOUS: PREVIOUS_KEY_COMMENT });
  ensureGitignored(dir, ".env.local");

  console.log(`✔ Daywalker configured${slug ? ` (audience "${slug}")` : ""}${domain ? ` (${domain})` : ""}`);
  console.log(`  • RFC 9421 / RFC 9530 HTTP Message Signing active`);
  console.log(`  • .env.local: ${slug ? "DAYWALKER_SERVICE_SLUG, " : ""}DAYWALKER_KEY_ID, DAYWALKER_AUTH_URL${domain ? ", DAYWALKER_DOMAIN" : ""}${apiKey ? ", DAYWALKER_API_KEY" : ""}${signingKeyStr ? ", DAYWALKER_SIGNING_KEY" : ""}`);
  if (kid) console.log(`  • Key ID (RFC 7638 thumbprint): ${kid}`);
  if (registered) console.log(`  • Zero-ingress push architecture: public key registered directly`);
  if (previousKey) {
    const previousKid = (await loadSigningKey(previousKey).catch(() => null))?.publicJwk.kid;
    console.log(`  • Previous key kept as DAYWALKER_SIGNING_KEY_PREVIOUS for rollback; it stays registered.`);
    if (previousKid) console.log(`    Once the new key is deployed everywhere: npx daywalker revoke ${previousKid}`);
  }

  if (opts["print-key"] && signingKeyStr) console.log(`\nDAYWALKER_SIGNING_KEY=${signingKeyStr}`);
}

async function rotate(opts: Record<string, string | boolean>) {
  const isJson = Boolean(opts.json || opts.export);
  const dir = process.cwd();
  const envFile = path.join(dir, ".env.local");
  const existing = readEnvFile(envFile);
  const current = existing.get("DAYWALKER_SIGNING_KEY") ?? process.env.DAYWALKER_SIGNING_KEY;
  if (!current) fail("No DAYWALKER_SIGNING_KEY found; run `daywalker init` first");

  const slug = parseServiceSlugs(String(opts.service ?? existing.get("DAYWALKER_SERVICE_SLUG") ?? process.env.DAYWALKER_SERVICE_SLUG ?? "")).join(",");
  const apiKey = await resolveApiKey(opts, existing);
  const authUrl = String(opts["auth-url"] ?? existing.get("DAYWALKER_AUTH_URL") ?? process.env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");

  const rotateDomain = publicHostname(String(opts.domain ?? existing.get("DAYWALKER_DOMAIN") ?? process.env.DAYWALKER_DOMAIN ?? ""));
  const key = await generateSigningKey();

  // The new key only becomes active once Daywalker Auth knows it, so registration must succeed
  // before anything is written (unless the caller explicitly registers it some other way).
  if (!skipRegister(opts)) {
    if (!apiKey) {
      fail("rotate needs DAYWALKER_API_KEY to register the new key (or pass --skip-register to write it unregistered)");
    }
    if (!isJson) console.log(`• Registering new public key (${key.publicJwk.kid}) with Daywalker Auth...`);
    const regResult = await registerPublicKey({
      authUrl,
      apiKey,
      domain: rotateDomain,
      publicJwk: key.publicJwk,
      instanceId: keySlotFor(key.publicJwk.kid),
    });
    if (!regResult.ok) {
      fail(`${keyApiFailure("Key registration", regResult)}\n  Nothing was written; the current key is still active.`);
    }
    if (!isJson) console.log(`✔ New public key registered with Daywalker Auth`);
  }

  const envValues = {
    DAYWALKER_KEY_ID: key.publicJwk.kid,
    DAYWALKER_SIGNING_KEY: key.privateKeyPkcs8Base64 ?? "",
    // Kept for rollback: services still signing with the old key keep working during rollout.
    DAYWALKER_SIGNING_KEY_PREVIOUS: current,
  };

  if (isJson) {
    warnJsonIncludesKey(envValues);
    console.log(JSON.stringify(envValues, null, 2));
    return;
  }

  writeEnvFile(envFile, envValues, { DAYWALKER_SIGNING_KEY_PREVIOUS: PREVIOUS_KEY_COMMENT });
  console.log(`✔ New key ${key.publicJwk.kid} written; previous key preserved as DAYWALKER_SIGNING_KEY_PREVIOUS.`);
  const previousKid = (await loadSigningKey(current).catch(() => null))?.publicJwk.kid;
  console.log(`  The previous key stays registered, so running deployments keep working.`);
  if (previousKid) console.log(`  Once the new key is deployed everywhere: npx daywalker revoke ${previousKid}, then remove DAYWALKER_SIGNING_KEY_PREVIOUS.`);

  if (opts["print-key"]) console.log(`\nDAYWALKER_SIGNING_KEY=${key.privateKeyPkcs8Base64}`);
}

async function check(opts: Record<string, string | boolean>) {
  const env = { ...process.env, ...Object.fromEntries(readEnvFile(path.join(process.cwd(), ".env.local"))) };
  const client = createDaywalker({ env });
  const result = await client.selfCheck();

  if (result.ok && !opts.offline) {
    const live = await client.validateServiceCredentials();
    if (!live.ok) {
      result.ok = false;
      result.problems.push(`OAuth client credentials check failed (${live.status} ${live.error}): ${live.message}`);
    } else {
      console.log(`✔ OAuth client credentials grant succeeded (services: ${(live.data.services ?? []).join(", ")})`);
    }
  }

  if (result.ok) {
    console.log(`✔ Daywalker configuration looks good`);
    if (result.serviceSlugs.length > 1) console.log(`  • Services: ${result.serviceSlugs.join(", ")} (default: ${result.serviceSlug})`);
    else if (result.serviceSlug) console.log(`  • Service slug: ${result.serviceSlug}`);
    if (result.domain) console.log(`  • Caller domain: ${result.domain}`);
    if (result.keyId) console.log(`  • Key ID: ${result.keyId}`);
    if (result.signing) console.log(`  • RFC 9421 signature signing: ready`);
    if (result.offlineVerificationReady) console.log(`  • Zero-egress offline JWT lease verification: ready`);
    return;
  }

  console.error(`✖ Daywalker self-check found problems:`);
  for (const p of result.problems) console.error(redactSecrets(`  - ${p}`));
  process.exit(1);
}

/** Domain, API key and auth URL for the key commands, from flags, .env.local or the environment. */
async function keyCommandContext(opts: Record<string, string | boolean>) {
  const existing = readEnvFile(path.join(process.cwd(), ".env.local"));
  const apiKey = await resolveApiKey(opts, existing);
  if (!apiKey) fail("Set DAYWALKER_API_KEY (or pipe it to --api-key-stdin)");
  const rawDomain = String(opts.domain ?? existing.get("DAYWALKER_DOMAIN") ?? process.env.DAYWALKER_DOMAIN ?? "");
  const domain = publicHostname(rawDomain);
  const authUrl = String(opts["auth-url"] ?? existing.get("DAYWALKER_AUTH_URL") ?? process.env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");
  const currentKid = existing.get("DAYWALKER_KEY_ID") ?? process.env.DAYWALKER_KEY_ID ?? null;
  const previous = existing.get("DAYWALKER_SIGNING_KEY_PREVIOUS") ?? process.env.DAYWALKER_SIGNING_KEY_PREVIOUS;
  const previousKid = previous ? ((await loadSigningKey(previous).catch(() => null))?.publicJwk.kid ?? null) : null;
  return { apiKey, domain, rawDomain, authUrl, currentKid, previousKid };
}

async function keys(opts: Record<string, string | boolean>) {
  const ctx = await keyCommandContext(opts);
  if (!ctx.domain) fail(`--domain (${ctx.rawDomain || "not set"}) must be a public hostname (or set DAYWALKER_DOMAIN)`);
  const result = await listSigningKeys({ authUrl: ctx.authUrl, apiKey: ctx.apiKey, domain: ctx.domain });
  if (!result.ok) fail(keyApiFailure("Listing keys", result));
  const list = result.keys ?? [];
  if (opts.json) {
    console.log(JSON.stringify(list, null, 2));
    return;
  }
  const when = (t: number | null) => (t === null ? "-" : new Date(t * 1000).toISOString().replace(/\.\d{3}Z$/, "Z"));
  console.log(`Signing keys for ${ctx.domain} (${list.filter((k) => k.status !== "REVOKED").length} live of 20 allowed):`);
  for (const k of list) {
    const tag = k.keyId === ctx.currentKid ? " (current)" : k.keyId === ctx.previousKid ? " (previous)" : "";
    console.log(`  ${k.keyId}${tag}  ${k.status}  slot=${k.instanceId ?? "-"}  expires=${when(k.expiresAt)}  lastUsed=${when(k.lastUsedAt)}`);
  }
}

async function revoke(keyId: string | undefined, opts: Record<string, string | boolean>) {
  if (!keyId) fail("Usage: daywalker revoke <keyId>");
  const ctx = await keyCommandContext(opts);
  if (keyId === ctx.currentKid && !opts.force) {
    fail(`${keyId} is DAYWALKER_KEY_ID, the key this service signs with: revoking it stops this service from authenticating. Pass --force if that is what you want.`);
  }
  const result = await revokeSigningKey({ authUrl: ctx.authUrl, apiKey: ctx.apiKey, keyId });
  if (!result.ok) fail(keyApiFailure(`Revoking ${keyId}`, result));
  console.log(`✔ Revoked signing key ${keyId}; Daywalker ended the OAuth sessions it started.`);
  if (keyId === ctx.previousKid) console.log("  You can now remove DAYWALKER_SIGNING_KEY_PREVIOUS from .env.local.");
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const parsedArgs = args(rest);

  if (parsedArgs["api-key"] !== undefined) {
    fail("--api-key is not supported: it exposes the key in shell history and process listings. Use DAYWALKER_API_KEY in the environment or .env.local, or pipe it to --api-key-stdin.");
  }

  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    console.log(HELP);
    return;
  }

  if (cmd === "onboard") {
    const result = await runOnboard(parsedArgs, { init, readEnvFile, writeEnvFile, ensureGitignored });
    if (result.exitCode) process.exit(result.exitCode);
  } else if (cmd === "init") {
    await init(parsedArgs);
  } else if (cmd === "rotate") {
    await rotate(parsedArgs);
  } else if (cmd === "check") {
    await check(parsedArgs);
  } else if (cmd === "keys") {
    await keys(parsedArgs);
  } else if (cmd === "license") {
    const sub = rest[0];
    if (sub !== "apply" && sub !== "check") fail("Usage: daywalker license apply|check [--dir <path>] (see --help)");
    const list = (v: string | boolean | undefined) => (typeof v === "string" ? v.split(",").map((x) => x.trim()).filter(Boolean) : undefined);
    const dir = path.resolve(typeof parsedArgs.dir === "string" ? parsedArgs.dir : ".");
    if (!fs.existsSync(dir)) fail(`--dir ${dir} does not exist`);
    const opts = {
      dir,
      dryRun: Boolean(parsedArgs["dry-run"]),
      replaceExisting: Boolean(parsedArgs["replace-existing"]),
      include: list(parsedArgs.include),
      exclude: list(parsedArgs.exclude),
      guardNames: list(parsedArgs["guard-names"]),
      governingLaw: typeof parsedArgs["governing-law"] === "string" ? parsedArgs["governing-law"] : undefined,
    };
    const report = sub === "apply" ? applyLicense(opts) : checkLicense(opts);
    console.log(formatReport(report, sub, opts.dryRun));
    if (sub === "check" && report.problems.length) process.exit(1);
  } else if (cmd === "revoke") {
    await revoke(rest[0] && !rest[0].startsWith("--") ? rest[0] : undefined, parsedArgs);
  } else {
    fail(`Unknown command "${cmd}". Run \`daywalker --help\` for usage.`);
  }
}

main().catch((err) => {
  console.error(redactSecrets(String((err as Error)?.stack || err)));
  process.exit(1);
});
