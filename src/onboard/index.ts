import fs from "node:fs";
import path from "node:path";
import { publicHostname } from "../config.js";
import { createApi, DEFAULT_AUTH_URL, OnboardApiError, type OnboardApi } from "./api.js";
import { collectHookEnv, HOOK_FILE, hookNextSteps, loadHook } from "./hooks.js";
import { createPrompter, type Prompter } from "./prompts.js";
import {
  buildAllowedOrigins,
  createToken,
  DEFAULT_LOCAL_ORIGIN,
  extractToken,
  listServices,
  login,
  normalizeAppUrl,
  signup,
  stageAtLeast,
  validatePassword,
  verifyEmail,
  type OnboardState,
  type ServiceInfo,
} from "./steps.js";

export const STATE_FILE = ".daywalker-onboard.json";

export type OnboardOptions = Record<string, string | boolean>;

/** Pieces of the CLI that onboarding reuses in-process (kept in cli.ts, which runs on import). */
export interface OnboardDeps {
  init(opts: OnboardOptions): Promise<void>;
  readEnvFile(file: string): Map<string, string>;
  writeEnvFile(file: string, values: Record<string, string | null>, comments?: Record<string, string>): void;
  ensureGitignored(dir: string, entry: string): void;
}

export interface OnboardContext {
  cwd?: string;
  api?: OnboardApi;
  /** null means non-interactive: every answer must come from flags or the environment. */
  prompter?: Prompter | null;
  log?: (message: string) => void;
  env?: NodeJS.ProcessEnv;
}

export interface OnboardResult {
  exitCode: number;
  service?: string;
  domain?: string;
}

function str(value: string | boolean | undefined): string {
  return typeof value === "string" ? value : "";
}

function loadState(file: string): OnboardState {
  try {
    const parsed = JSON.parse(fs.readFileSync(file, "utf8"));
    return { stage: "new", ...parsed };
  } catch {
    return { stage: "new" };
  }
}

/** Only non-secret fields are persisted: never the password, token or keys. */
function saveState(file: string, state: OnboardState, dryRun: boolean) {
  if (dryRun) return;
  const { stage, name, email, domain, service } = state;
  // Never write through a symlink (a checked-in one could point at any file the user can write).
  if (fs.lstatSync(file, { throwIfNoEntry: false })?.isSymbolicLink()) throw new Error(`${STATE_FILE} is a symlink; refusing to write through it`);
  fs.writeFileSync(file, `${JSON.stringify({ stage, name, email, domain, service }, null, 2)}\n`, { mode: 0o600 });
}

async function readPassword(prompter: Prompter | null, env: NodeJS.ProcessEnv, log: (m: string) => void, strict: boolean): Promise<string> {
  if (env.DAYWALKER_ONBOARD_PASSWORD) return env.DAYWALKER_ONBOARD_PASSWORD;
  if (!prompter) throw new Error("Set DAYWALKER_ONBOARD_PASSWORD for non-interactive use.");
  for (;;) {
    const password = await prompter.hidden("Daywalker password" + (strict ? " (min 12 chars, 3 of: a-z A-Z 0-9 symbol)" : ""));
    const problem = strict ? validatePassword(password) : password ? null : "Password is required";
    if (problem) {
      log(problem);
      continue;
    }
    if (!strict || password === (await prompter.hidden("Confirm password"))) return password;
    log("Passwords did not match.");
  }
}

async function chooseService(
  services: ServiceInfo[],
  requested: string,
  prompter: Prompter | null,
  log: (m: string) => void
): Promise<ServiceInfo> {
  if (requested) {
    const found = services.find((s) => s.slug === requested);
    if (!found) throw new Error(`Service '${requested}' was not found or is not visible to this account.`);
    return found;
  }
  if (services.length === 0) throw new Error("This account can see no services yet. Ask the service owner for access, then re-run.");
  if (!prompter) throw new Error("Pass --service <slug> for non-interactive use.");
  log("\nAvailable services:");
  services.forEach((s, i) => log(`  ${i + 1}. ${s.name ?? s.slug} (${s.slug})${s.status ? ` [${s.status}]` : ""}`));
  for (;;) {
    const answer = (await prompter.ask("Which service do you want to set up? (number or slug)")).trim();
    const byIndex = /^\d+$/.test(answer) ? services[Number(answer) - 1] : undefined;
    const chosen = byIndex ?? services.find((s) => s.slug === answer);
    if (chosen) return chosen;
    log("Pick a number from the list or a slug.");
  }
}

async function chooseDomain(requested: string, prompter: Prompter | null, log: (m: string) => void): Promise<string> {
  let origin = normalizeAppUrl(requested);
  if (requested && !origin) throw new Error(`--url (${requested}) must be a public https URL.`);
  while (!origin) {
    if (!prompter) throw new Error("Pass --url <https://your.public.app> for non-interactive use.");
    origin = normalizeAppUrl(await prompter.ask("Public app URL (e.g. https://app.example.com)"));
    if (!origin) log("Enter a public https URL (not localhost or an IP address).");
  }
  return origin;
}

/** `daywalker onboard`: account, verification, service choice, token, key registration. */
export async function runOnboard(opts: OnboardOptions, deps: OnboardDeps, ctx: OnboardContext = {}): Promise<OnboardResult> {
  const cwd = ctx.cwd ?? process.cwd();
  const env = ctx.env ?? process.env;
  const log = ctx.log ?? ((m: string) => console.log(m));
  const dry = Boolean(opts["dry-run"]);
  const interactive = ctx.prompter !== undefined ? ctx.prompter !== null : Boolean(process.stdin.isTTY) && !opts.yes;
  const prompter = ctx.prompter !== undefined ? ctx.prompter : interactive ? createPrompter() : null;
  const authUrl = str(opts["auth-url"]) || env.DAYWALKER_AUTH_URL || DEFAULT_AUTH_URL;
  const statePath = path.join(cwd, STATE_FILE);
  const envFile = path.join(cwd, ".env.local");

  try {
    const api = ctx.api ?? createApi({ baseUrl: authUrl });
    if (dry) log("Dry run: no network calls, no files written.\n");
    const state = loadState(statePath);
    let requestedService = str(opts.service) || state.service || "";
    if (requestedService && !/^[a-z0-9_-]+$/.test(requestedService)) throw new Error("--service must be a Daywalker service slug.");

    state.name = str(opts.name) || state.name || (prompter ? await prompter.ask("Your name") : "");
    state.email = str(opts.email) || state.email || (prompter ? await prompter.ask("Email address") : "");
    if (!state.name || !state.email || !/^\S+@\S+\.\S+$/.test(state.email)) throw new Error("A name and a valid email are required (--name, --email).");

    if (dry) {
      log(`Would sign up or log in ${state.email} and wait for email verification.`);
      log(`Would list services${requestedService ? ` and use '${requestedService}'` : " and ask which one to set up"}.`);
      log(`Would ask for the public app URL, then create a token allowing: <app url>, ${DEFAULT_LOCAL_ORIGIN}`);
      log("Would run `daywalker init --domain <host> --service <slug>` in-process and write .env.local.");
      if (fs.existsSync(path.join(cwd, HOOK_FILE))) log(`Would ask to run ${HOOK_FILE} (project prompts and env values). Not executed in a dry run.`);
      return { exitCode: 0 };
    }

    const hook = await loadHook(cwd, { trusted: Boolean(opts.yes), prompter, log });
    requestedService ||= hook?.defaultService ?? "";
    const localOrigins = hook?.localOrigins?.length ? hook.localOrigins : [DEFAULT_LOCAL_ORIGIN];

    deps.ensureGitignored(cwd, STATE_FILE);
    const existingEnv = deps.readEnvFile(envFile);
    const hasKey = Boolean(existingEnv.get("DAYWALKER_API_KEY"));

    if (!(stageAtLeast(state, "token_created") && hasKey)) {
      let password: string | null = null;

      if (!stageAtLeast(state, "signed_up")) {
        const existing = prompter ? await prompter.confirm("Do you already have a Daywalker account?", false) : Boolean(opts["existing-account"]);
        if (existing) {
          state.stage = "verified";
        } else {
          password = await readPassword(prompter, env, log, true);
          await signup(api, { name: state.name, email: state.email, password, serviceSlug: requestedService || undefined });
          state.stage = "signed_up";
          log(`\n✔ Account request sent. Check ${state.email} for the verification link.`);
        }
        saveState(statePath, state, dry);
      }

      if (!stageAtLeast(state, "verified")) {
        const answer = prompter
          ? await prompter.ask("Paste the verification link or token from the email (blank to stop and resume later)")
          : env.DAYWALKER_ONBOARD_VERIFY_TOKEN || "";
        const token = extractToken(answer);
        if (!token) {
          log("\nStopped before verification. Verify your email, then re-run `daywalker onboard` to resume.");
          return { exitCode: 2 };
        }
        await verifyEmail(api, token);
        state.stage = "verified";
        saveState(statePath, state, dry);
        log("✔ Email verified.");
      }

      password ??= await readPassword(prompter, env, log, false);
      const session = await login(api, { email: state.email, password });

      const services = await listServices(api, session);
      const service = await chooseService(services, requestedService, prompter, log);
      state.service = service.slug;

      const origin = await chooseDomain(str(opts.url) || state.domain || "", prompter, log);
      state.domain = origin;

      if (hasKey) {
        const replace = prompter ? await prompter.confirm("DAYWALKER_API_KEY already exists in .env.local. Replace it?", false) : Boolean(opts.yes);
        if (!replace) throw new Error("Kept the existing DAYWALKER_API_KEY. Remove it from .env.local (or pass --yes) to create a new token.");
      }

      const apiKey = await createToken(api, session, {
        serviceId: service.id,
        slug: service.slug,
        allowedOrigins: buildAllowedOrigins(origin, localOrigins),
      });
      deps.writeEnvFile(envFile, { DAYWALKER_API_KEY: apiKey });
      state.stage = "token_created";
      saveState(statePath, state, dry);
      log("✔ API token created and saved to .env.local (shown only once; never printed).");
    }

    const slug = state.service;
    const host = publicHostname(state.domain ?? "");
    if (!slug || !host) throw new Error(`Saved state is incomplete; delete ${STATE_FILE} and re-run.`);

    if (!stageAtLeast(state, "registered")) {
      // Register the key with the same Daywalker Auth the token was created on.
      await deps.init({ service: slug, domain: host, ...(authUrl !== DEFAULT_AUTH_URL ? { "auth-url": authUrl } : {}) });
      state.stage = "registered";
      saveState(statePath, state, dry);
    }

    if (hook) {
      const values = await collectHookEnv(hook, { existing: deps.readEnvFile(envFile), prompter, env, log, replaceExisting: Boolean(opts.yes) });
      if (Object.keys(values).length) {
        deps.writeEnvFile(envFile, values);
        log(`✔ .env.local updated by ${HOOK_FILE} (${Object.keys(values).join(", ")}).`);
      }
    }

    log(`\n✔ ${slug} is set up for ${host}.`);
    const steps = hookNextSteps(hook, { slug, domain: host, localOrigins });
    if (steps.length) {
      log("Next steps:");
      steps.forEach((s, i) => log(`  ${i + 1}. ${s}`));
    } else {
      log("Next steps: start your app; Daywalker values are in .env.local.");
    }
    fs.rmSync(statePath, { force: true });
    return { exitCode: 0, service: slug, domain: host };
  } catch (err) {
    const message = err instanceof OnboardApiError ? err.message : (err as Error).message || String(err);
    console.error(`\n✖ ${message}`);
    return { exitCode: 1 };
  } finally {
    prompter?.close();
  }
}
