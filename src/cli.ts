#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { createDaywalker } from "./client.js";
import { publicHostname } from "./config.js";
import { generateSigningKey } from "./signing.js";

const HELP = `daywalker: connect a service to Daywalker Auth

Usage:
  daywalker init   --domain <host> --service <slug> [--do-app <name|id>] [--framework next|express] [--print-key]
  daywalker rotate [--do-app <name|id>] [--print-key]
  daywalker check

init     Generates a signing key, adds the /.well-known/daywalker-keys.json route for your
         framework, and writes DAYWALKER_* settings to .env.local. With --do-app it also sets
         them on your DigitalOcean App Platform app (as an encrypted secret, via doctl).
rotate   Generates a new key and keeps the old one published as DAYWALKER_SIGNING_KEY_PREVIOUS,
         so requests signed with either key verify during the switch. Remove the previous key
         a few minutes after deploying.
check    Validates config and confirms your domain serves the current public key.

The private key is never printed unless you pass --print-key.`;

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
  console.error(`✖ ${message}`);
  process.exit(1);
}

// --- .env.local ---------------------------------------------------------------

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

// --- framework route ------------------------------------------------------------

function detectFramework(dir: string): "next" | "express" | null {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8"));
    const deps = { ...pkg.dependencies, ...pkg.devDependencies };
    if (deps.next) return "next";
    if (deps.express || deps.fastify || deps.koa || deps.hono) return "express";
  } catch {
    // no package.json
  }
  return null;
}

function addNextRoute(dir: string): string {
  const appDir = ["src/app", "app"].map((d) => path.join(dir, d)).find((d) => fs.existsSync(d)) ?? path.join(dir, "app");
  const routeDir = path.join(appDir, ".well-known", "daywalker-keys.json");
  const routeFile = path.join(routeDir, "route.ts");
  const rel = path.relative(dir, routeFile);
  if (fs.existsSync(routeFile)) return `${rel} already exists (left unchanged)`;
  // A static file here would shadow the route and pin an old key
  const staticFile = path.join(dir, "public", ".well-known", "daywalker-keys.json");
  if (fs.existsSync(staticFile)) console.warn(`! Remove ${path.relative(dir, staticFile)}; the route serves keys from env now.`);
  fs.mkdirSync(routeDir, { recursive: true });
  fs.writeFileSync(
    routeFile,
    `// Serves this service's public signing key so Daywalker Auth can verify its requests.\nexport { GET, dynamic } from "@shelbyb/daywalker-sdk/next";\n`
  );
  return `created ${rel}`;
}

// --- DigitalOcean ---------------------------------------------------------------

function setDigitalOceanEnv(app: string, values: Record<string, { value: string | null; secret: boolean }>) {
  const doctl = (a: string[], input?: string) =>
    execFileSync("doctl", a, { encoding: "utf8", input, stdio: [input ? "pipe" : "ignore", "pipe", "pipe"] });
  let appId = app;
  if (!/^[0-9a-f-]{36}$/.test(app)) {
    const apps = JSON.parse(doctl(["apps", "list", "--output", "json"])) as { id: string; spec: { name: string } }[];
    appId = apps.find((a) => a.spec.name === app)?.id ?? fail(`No DigitalOcean app named "${app}"`);
  }
  const spec = JSON.parse(doctl(["apps", "spec", "get", appId, "--format", "json"]));
  const components = [...(spec.services ?? []), ...(spec.workers ?? []), ...(spec.jobs ?? [])];
  if (!components.length) fail("The app spec has no services, workers, or jobs to configure");
  for (const component of components) {
    component.envs = (component.envs ?? []).filter((e: { key: string }) => !(e.key in values));
    for (const [key, { value, secret }] of Object.entries(values)) {
      if (value !== null) component.envs.push({ key, value, scope: "RUN_TIME", ...(secret ? { type: "SECRET" } : {}) });
    }
  }
  // Spec goes in via stdin so secrets never appear in process arguments
  doctl(["apps", "update", appId, "--spec", "-", "--output", "json"], JSON.stringify(spec));
  return appId;
}

// --- commands ---------------------------------------------------------------

async function init(opts: Record<string, string | boolean>) {
  const dir = process.cwd();
  const envFile = path.join(dir, ".env.local");
  const existing = readEnvFile(envFile);
  const domain = publicHostname(String(opts.domain ?? existing.get("DAYWALKER_DOMAIN") ?? ""));
  if (!domain) fail("--domain must be the public hostname that serves this app, e.g. --domain sonalyze.daywalker.dev");
  const slug = String(opts.service ?? existing.get("DAYWALKER_SERVICE_SLUG") ?? "").trim().toLowerCase();
  if (!/^[a-z0-9_-]+$/.test(slug)) fail("--service must be this service's Daywalker slug, e.g. --service sonalyze");

  const keyExists = Boolean(existing.get("DAYWALKER_SIGNING_KEY")) && !opts.force;
  const key = keyExists ? null : generateSigningKey();

  const framework = (opts.framework as string) || detectFramework(dir);
  let routeNote: string;
  if (framework === "next") routeNote = addNextRoute(dir);
  else if (framework === "express") routeNote = `add app.use(daywalkerKeys()) from "@shelbyb/daywalker-sdk/express" before your routes`;
  else routeNote = `serve GET /.well-known/daywalker-keys.json with daywalker().keys() (see the SDK README)`;

  writeEnvFile(envFile, {
    DAYWALKER_SERVICE_SLUG: slug,
    DAYWALKER_DOMAIN: domain,
    ...(key ? { DAYWALKER_SIGNING_KEY: key.privateKey } : {}),
  });
  ensureGitignored(dir, ".env.local");

  console.log(`✔ Daywalker configured for ${domain} (service "${slug}")`);
  console.log(`  • ${routeNote}`);
  console.log(`  • .env.local: DAYWALKER_SERVICE_SLUG, DAYWALKER_DOMAIN${key ? ", DAYWALKER_SIGNING_KEY" : " (kept existing signing key)"}`);
  if (key) console.log(`  • key id ${key.publicJwk.kid}`);

  if (opts["do-app"]) {
    const signingKey = key?.privateKey ?? existing.get("DAYWALKER_SIGNING_KEY")!;
    const appId = setDigitalOceanEnv(String(opts["do-app"]), {
      DAYWALKER_SERVICE_SLUG: { value: slug, secret: false },
      DAYWALKER_DOMAIN: { value: domain, secret: false },
      DAYWALKER_SIGNING_KEY: { value: signingKey, secret: true },
    });
    console.log(`  • DigitalOcean app ${appId}: env vars set (signing key encrypted); a redeploy has started`);
    console.log(`    Pull the updated spec into .do/app.yaml before your next spec deploy, or the key will be removed.`);
  } else {
    console.log(`  • Production: set DAYWALKER_SERVICE_SLUG, DAYWALKER_DOMAIN, and DAYWALKER_SIGNING_KEY (as a secret)`);
    console.log(`    on your host, or re-run with --do-app <name> for DigitalOcean App Platform.`);
  }
  if (opts["print-key"] && key) console.log(`\nDAYWALKER_SIGNING_KEY=${key.privateKey}`);
  console.log(`\nNext: deploy, then run \`npx daywalker check\`, and add ${domain} (or *.${domain.split(".").slice(1).join(".")}) to your token's allowed callers.`);
}

async function rotate(opts: Record<string, string | boolean>) {
  const envFile = path.join(process.cwd(), ".env.local");
  const existing = readEnvFile(envFile);
  const current = existing.get("DAYWALKER_SIGNING_KEY");
  if (!current) fail("No DAYWALKER_SIGNING_KEY in .env.local; run `daywalker init` first");
  const key = generateSigningKey();
  writeEnvFile(envFile, { DAYWALKER_SIGNING_KEY: key.privateKey, DAYWALKER_SIGNING_KEY_PREVIOUS: current });
  console.log(`✔ New key ${key.publicJwk.kid} written; the old key stays published as DAYWALKER_SIGNING_KEY_PREVIOUS.`);
  if (opts["do-app"]) {
    const appId = setDigitalOceanEnv(String(opts["do-app"]), {
      DAYWALKER_SIGNING_KEY: { value: key.privateKey, secret: true },
      DAYWALKER_SIGNING_KEY_PREVIOUS: { value: current, secret: true },
    });
    console.log(`  • DigitalOcean app ${appId} updated; a redeploy has started.`);
  }
  console.log(`  After the deploy is live, remove DAYWALKER_SIGNING_KEY_PREVIOUS to retire the old key.`);
  if (opts["print-key"]) console.log(`\nDAYWALKER_SIGNING_KEY=${key.privateKey}`);
}

async function check() {
  // Merge .env.local over the process env, like Next.js does in development
  const env = { ...process.env, ...Object.fromEntries(readEnvFile(path.join(process.cwd(), ".env.local"))) };
  const result = await createDaywalker({ env }).selfCheck();
  console.log(`domain:  ${result.domain ?? "(none)"}`);
  console.log(`keys:    ${result.keysUrl ?? "(none)"}`);
  console.log(`signing: ${result.signing ? "yes" : "no"}`);
  if (result.ok) console.log("✔ Ready: requests will be signed and your key is published.");
  else {
    for (const p of result.problems) console.log(`✖ ${p}`);
    process.exit(1);
  }
}

const [command, ...rest] = process.argv.slice(2);
const opts = args(rest);
const commands: Record<string, (o: typeof opts) => Promise<void>> = { init, rotate, check };
if (!command || !commands[command] || opts.help) {
  console.log(HELP);
  process.exit(command && !opts.help ? 1 : 0);
}
commands[command](opts).catch((err) => fail((err as Error).message));
