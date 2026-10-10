#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";
import { createDaywalker } from "./client.js";
import { publicHostname } from "./config.js";
import { generateSigningKey, loadSigningKey, registerPublicKey, redactSecrets } from "./crypto/index.js";

const HELP = `daywalker: connect a service to Daywalker Auth (RFC 9421 / Push Architecture)

Usage:
  daywalker init   --service <slug> [--api-key <key>] [--domain <host>] [--auth-url <url>] [--json|--export] [--print-key]
  daywalker rotate [--service <slug>] [--api-key <key>] [--auth-url <url>] [--json|--export] [--print-key]
  daywalker check

init     Generates an Ed25519 keypair, registers the public key directly with Daywalker Auth
         (POST /api/v1/keys/register), and writes DAYWALKER_* settings to .env.local (or outputs JSON with --json).
         No public ingress or /.well-known route handlers are required.
rotate   Generates a new Ed25519 key, registers it with Daywalker Auth, and keeps the old one
         in .env.local as DAYWALKER_SIGNING_KEY_PREVIOUS during deployment transition.
check    Validates configuration and confirms Daywalker Auth connection and signature readiness.

Options:
  --json, --export  Output configuration as JSON for piping into Vercel, DigitalOcean, Fly.io, AWS SSM, etc.
  --print-key       Print the private key to stdout (disabled by default for security).
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

function readEnvFile(file: string): Map<string, string> {
  const map = new Map<string, string>();
  if (!fs.existsSync(file)) return map;
  for (const line of fs.readFileSync(file, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*)$/);
    if (m) map.set(m[1], m[2].replace(/^"(.*)"$/, "$1"));
  }
  return map;
}

function writeEnvFile(file: string, values: Record<string, string | null>) {
  const lines = fs.existsSync(file) ? fs.readFileSync(file, "utf8").split("\n") : [];
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
    out.push("# Daywalker Auth (managed by `daywalker init`)", ...added.map(([k, v]) => `${k}="${v}"`));
  }
  fs.writeFileSync(file, out.join("\n") + "\n", { mode: 0o600 });
}

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

  const slug = String(opts.service ?? existing.get("DAYWALKER_SERVICE_SLUG") ?? process.env.DAYWALKER_SERVICE_SLUG ?? "")
    .trim()
    .toLowerCase();
  if (!slug || !/^[a-z0-9_-]+$/.test(slug)) {
    fail("--service must be this service's Daywalker slug (e.g. --service sonalyze)");
  }

  const rawDomain = opts.domain ? String(opts.domain) : existing.get("DAYWALKER_DOMAIN") ?? process.env.DAYWALKER_DOMAIN ?? "";
  let domain: string | null = null;
  if (rawDomain) {
    domain = publicHostname(rawDomain);
    if (!domain) fail(`--domain (${rawDomain}) is not a valid public hostname`);
  }

  const apiKey = String(opts["api-key"] ?? existing.get("DAYWALKER_API_KEY") ?? process.env.DAYWALKER_API_KEY ?? "").trim() || null;
  const authUrl = String(opts["auth-url"] ?? existing.get("DAYWALKER_AUTH_URL") ?? process.env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");

  const keyExists = Boolean(existing.get("DAYWALKER_SIGNING_KEY")) && !opts.force;
  const key = keyExists ? null : await generateSigningKey();

  const activeKey = key ?? (existing.get("DAYWALKER_SIGNING_KEY") ? await loadSigningKey(existing.get("DAYWALKER_SIGNING_KEY")!) : null);
  const kid = activeKey?.publicJwk.kid ?? String(opts["key-id"] ?? "");

  // Register public key directly with Daywalker Auth if API key is provided
  let registered = false;
  if (apiKey && activeKey && !opts["skip-register"]) {
    if (!isJson) console.log(`• Registering public key (${activeKey.publicJwk.kid}) with Daywalker Auth...`);
    const regResult = await registerPublicKey({
      authUrl,
      apiKey,
      serviceSlug: slug,
      domain,
      publicJwk: activeKey.publicJwk,
    });
    if (regResult.ok) {
      registered = true;
      if (!isJson) console.log(`✔ Public key registered with Daywalker Auth (Push Architecture)`);
    } else {
      if (!isJson) {
        console.warn(redactSecrets(`! Key registration warning (${regResult.status}): ${regResult.error}`));
        console.warn(`  You can register the key later by re-running init with your DAYWALKER_API_KEY.`);
      }
    }
  } else if (!apiKey && !opts["skip-register"] && !isJson) {
    console.log(`• Note: Set DAYWALKER_API_KEY in .env.local to automatically register public keys.`);
  }

  const signingKeyStr = key?.privateKeyPkcs8Base64 ?? existing.get("DAYWALKER_SIGNING_KEY") ?? "";

  const envValues: Record<string, string | null> = {
    DAYWALKER_SERVICE_SLUG: slug,
    DAYWALKER_KEY_ID: kid,
    DAYWALKER_AUTH_URL: authUrl,
    ...(domain ? { DAYWALKER_DOMAIN: domain } : {}),
    ...(apiKey ? { DAYWALKER_API_KEY: apiKey } : {}),
    ...(signingKeyStr ? { DAYWALKER_SIGNING_KEY: signingKeyStr } : {}),
  };

  if (isJson) {
    console.log(JSON.stringify(envValues, null, 2));
    return;
  }

  writeEnvFile(envFile, envValues);
  ensureGitignored(dir, ".env.local");

  console.log(`✔ Daywalker configured for service "${slug}"${domain ? ` (${domain})` : ""}`);
  console.log(`  • RFC 9421 / RFC 9530 HTTP Message Signing active`);
  console.log(`  • .env.local: DAYWALKER_SERVICE_SLUG, DAYWALKER_KEY_ID, DAYWALKER_AUTH_URL${domain ? ", DAYWALKER_DOMAIN" : ""}${apiKey ? ", DAYWALKER_API_KEY" : ""}${signingKeyStr ? ", DAYWALKER_SIGNING_KEY" : ""}`);
  if (kid) console.log(`  • Key ID (RFC 7638 thumbprint): ${kid}`);
  if (registered) console.log(`  • Zero-ingress push architecture: public key registered directly`);

  if (opts["print-key"] && signingKeyStr) console.log(`\nDAYWALKER_SIGNING_KEY=${signingKeyStr}`);
}

async function rotate(opts: Record<string, string | boolean>) {
  const isJson = Boolean(opts.json || opts.export);
  const dir = process.cwd();
  const envFile = path.join(dir, ".env.local");
  const existing = readEnvFile(envFile);
  const current = existing.get("DAYWALKER_SIGNING_KEY") ?? process.env.DAYWALKER_SIGNING_KEY;
  if (!current) fail("No DAYWALKER_SIGNING_KEY found; run `daywalker init` first");

  const slug = String(opts.service ?? existing.get("DAYWALKER_SERVICE_SLUG") ?? process.env.DAYWALKER_SERVICE_SLUG ?? "").trim().toLowerCase();
  const apiKey = String(opts["api-key"] ?? existing.get("DAYWALKER_API_KEY") ?? process.env.DAYWALKER_API_KEY ?? "").trim() || null;
  const authUrl = String(opts["auth-url"] ?? existing.get("DAYWALKER_AUTH_URL") ?? process.env.DAYWALKER_AUTH_URL ?? "https://auth.daywalker.dev").replace(/\/+$/, "");

  const rotateDomain = publicHostname(String(opts.domain ?? existing.get("DAYWALKER_DOMAIN") ?? process.env.DAYWALKER_DOMAIN ?? ""));
  const key = await generateSigningKey();

  if (apiKey && slug) {
    if (!isJson) console.log(`• Registering new public key (${key.publicJwk.kid}) with Daywalker Auth...`);
    const regResult = await registerPublicKey({
      authUrl,
      apiKey,
      serviceSlug: slug,
      domain: rotateDomain,
      publicJwk: key.publicJwk,
    });
    if (regResult.ok) {
      if (!isJson) console.log(`✔ New public key registered with Daywalker Auth`);
    } else {
      if (!isJson) console.warn(redactSecrets(`! Key registration warning: ${regResult.error}`));
    }
  }

  const envValues = {
    DAYWALKER_KEY_ID: key.publicJwk.kid,
    DAYWALKER_SIGNING_KEY: key.privateKeyPkcs8Base64 ?? "",
    DAYWALKER_SIGNING_KEY_PREVIOUS: current,
  };

  if (isJson) {
    console.log(JSON.stringify(envValues, null, 2));
    return;
  }

  writeEnvFile(envFile, envValues);
  console.log(`✔ New key ${key.publicJwk.kid} written; previous key preserved as DAYWALKER_SIGNING_KEY_PREVIOUS.`);
  console.log(`  After deployment rollout is complete, you may remove DAYWALKER_SIGNING_KEY_PREVIOUS.`);

  if (opts["print-key"]) console.log(`\nDAYWALKER_SIGNING_KEY=${key.privateKeyPkcs8Base64}`);
}

async function check() {
  const env = { ...process.env, ...Object.fromEntries(readEnvFile(path.join(process.cwd(), ".env.local"))) };
  const client = createDaywalker({ env });
  const result = await client.selfCheck();

  if (result.ok) {
    console.log(`✔ Daywalker configuration looks good`);
    if (result.serviceSlug) console.log(`  • Service slug: ${result.serviceSlug}`);
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

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const parsedArgs = args(rest);

  if (!cmd || cmd === "--help" || cmd === "-h" || cmd === "help") {
    console.log(HELP);
    return;
  }

  if (cmd === "init") {
    await init(parsedArgs);
  } else if (cmd === "rotate") {
    await rotate(parsedArgs);
  } else if (cmd === "check") {
    await check();
  } else {
    fail(`Unknown command "${cmd}". Run \`daywalker --help\` for usage.`);
  }
}

main().catch((err) => {
  console.error(redactSecrets(String((err as Error)?.stack || err)));
  process.exit(1);
});
