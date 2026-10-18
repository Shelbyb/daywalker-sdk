import { randomBytes } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import type { Prompter } from "./prompts.js";

export const HOOK_FILE = "daywalker.onboard.mjs";

/** Same rule as `daywalker init` uses for .env.local: no quotes, `$`, backslashes or control characters. */
export const UNSAFE_ENV_VALUE = /["'`$\\\u0000-\u001f\u007f]/;
const ENV_KEY = /^[A-Z][A-Z0-9_]*$/;
const GENERATORS: Record<string, () => string> = {
  "base64-48": () => randomBytes(48).toString("base64"),
  "base64-32": () => randomBytes(32).toString("base64"),
  "hex-32": () => randomBytes(32).toString("hex"),
};

export interface HookEnvPrompt {
  key: string;
  label?: string;
  required?: boolean;
  hidden?: boolean;
  default?: string;
  mirrorTo?: string[];
}

export interface HookContext {
  slug: string;
  domain: string;
  localOrigins: string[];
}

export interface HookConfig {
  defaultService?: string;
  localOrigins?: string[];
  env?: HookEnvPrompt[];
  generate?: Record<string, string>;
  fixed?: Record<string, string>;
  nextSteps?: (ctx: HookContext) => string[] | string;
}

function checkKey(key: unknown, where: string): string {
  if (typeof key !== "string" || !ENV_KEY.test(key)) throw new Error(`${HOOK_FILE}: ${where} has an invalid env key (${String(key)})`);
  if (key.startsWith("DAYWALKER_")) throw new Error(`${HOOK_FILE}: ${where} may not set ${key}; DAYWALKER_* values are managed by the SDK`);
  return key;
}

function checkValue(key: string, value: unknown): string {
  if (typeof value !== "string") throw new Error(`${HOOK_FILE}: value for ${key} must be a string`);
  if (UNSAFE_ENV_VALUE.test(value)) {
    throw new Error(`${key} contains quotes, "$", backslashes, newlines or control characters; refusing to write it to .env.local`);
  }
  return value;
}

function isLocalOrigin(origin: string): boolean {
  try {
    const url = new URL(origin);
    if (url.protocol === "https:") return true;
    return url.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
  } catch {
    return false;
  }
}

/** Throws a readable error unless `raw` matches the documented shape. */
export function validateHook(raw: unknown): HookConfig {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error(`${HOOK_FILE} must default-export an object`);
  const c = raw as Record<string, any>;
  const out: HookConfig = {};
  if (c.defaultService !== undefined) {
    if (typeof c.defaultService !== "string" || !/^[a-z0-9_-]+$/.test(c.defaultService)) throw new Error(`${HOOK_FILE}: defaultService must be a service slug`);
    out.defaultService = c.defaultService;
  }
  if (c.localOrigins !== undefined) {
    if (!Array.isArray(c.localOrigins) || !c.localOrigins.every((o) => typeof o === "string" && isLocalOrigin(o))) {
      throw new Error(`${HOOK_FILE}: localOrigins must be https URLs (http only for localhost)`);
    }
    out.localOrigins = c.localOrigins;
  }
  if (c.env !== undefined) {
    if (!Array.isArray(c.env)) throw new Error(`${HOOK_FILE}: env must be an array`);
    out.env = c.env.map((e: any, i: number) => {
      const key = checkKey(e?.key, `env[${i}]`);
      const mirrorTo = e.mirrorTo === undefined ? undefined : (Array.isArray(e.mirrorTo) ? e.mirrorTo : []).map((k: unknown) => checkKey(k, `env[${i}].mirrorTo`));
      if (e.default !== undefined) checkValue(key, e.default);
      return { key, label: typeof e.label === "string" ? e.label : key, required: Boolean(e.required), hidden: Boolean(e.hidden), default: e.default, mirrorTo };
    });
  }
  if (c.generate !== undefined) {
    if (!c.generate || typeof c.generate !== "object") throw new Error(`${HOOK_FILE}: generate must be an object`);
    for (const [key, kind] of Object.entries(c.generate)) {
      checkKey(key, "generate");
      if (typeof kind !== "string" || !GENERATORS[kind]) throw new Error(`${HOOK_FILE}: generate.${key} must be one of ${Object.keys(GENERATORS).join(", ")}`);
    }
    out.generate = c.generate;
  }
  if (c.fixed !== undefined) {
    if (!c.fixed || typeof c.fixed !== "object") throw new Error(`${HOOK_FILE}: fixed must be an object`);
    for (const [key, value] of Object.entries(c.fixed)) checkValue(checkKey(key, "fixed"), value);
    out.fixed = c.fixed;
  }
  if (c.nextSteps !== undefined) {
    if (typeof c.nextSteps !== "function") throw new Error(`${HOOK_FILE}: nextSteps must be a function`);
    out.nextSteps = c.nextSteps;
  }
  return out;
}

/**
 * Loads `daywalker.onboard.mjs` from `cwd`. It is executable code, so the user must confirm unless
 * `trusted` (--yes) is set. Returns null when the file is absent or the user declines.
 */
export async function loadHook(
  cwd: string,
  opts: { trusted: boolean; prompter: Prompter | null; log: (m: string) => void }
): Promise<HookConfig | null> {
  const file = path.join(cwd, HOOK_FILE);
  if (!fs.existsSync(file)) return null;
  const allowed = opts.trusted || (opts.prompter ? await opts.prompter.confirm(`Run project setup from ${file}? (this executes code)`, false) : false);
  if (!allowed) {
    opts.log(`Skipped ${HOOK_FILE} (not confirmed; pass --yes to trust it).`);
    return null;
  }
  const mod = await import(pathToFileURL(file).href);
  return validateHook(mod.default);
}

export interface ApplyDeps {
  existing: Map<string, string>;
  prompter: Prompter | null;
  env: NodeJS.ProcessEnv;
  log: (m: string) => void;
  /** Non-interactive consent to replace existing values. */
  replaceExisting: boolean;
}

/** Computes the .env.local values the hook wants written. Existing values are kept unless confirmed. */
export async function collectHookEnv(config: HookConfig, deps: ApplyDeps): Promise<Record<string, string>> {
  const { existing, prompter, env, log } = deps;
  const updates: Record<string, string> = {};
  const mayReplace = async (key: string, label: string) =>
    prompter ? prompter.confirm(`${key} is already set. Replace it?`, false) : deps.replaceExisting;

  for (const [key, kind] of Object.entries(config.generate ?? {})) {
    if (!existing.get(key)) updates[key] = checkValue(key, GENERATORS[kind]());
  }

  for (const [key, value] of Object.entries(config.fixed ?? {})) {
    const current = existing.get(key);
    if (!current) updates[key] = value;
    else if (current !== value && (await mayReplace(key, key))) updates[key] = value;
  }

  for (const item of config.env ?? []) {
    const label = item.label ?? item.key;
    const current = existing.get(item.key);
    if (current && !(await mayReplace(item.key, label))) continue;
    let value = env[item.key] ?? "";
    if (!value && prompter) {
      const question = label + (item.required ? "" : " (optional)");
      value = item.hidden ? await prompter.hidden(question) : await prompter.ask(question, item.default ?? "");
    }
    if (!value && item.default && !prompter) value = item.default;
    if (!value) {
      if (item.required && !current) log(`⚠ ${item.key} is not set; add it to .env.local before starting the app.`);
      continue;
    }
    updates[item.key] = checkValue(item.key, value);
    for (const mirror of item.mirrorTo ?? []) updates[mirror] = updates[item.key];
  }
  return updates;
}

export function hookNextSteps(config: HookConfig | null, ctx: HookContext): string[] {
  if (!config?.nextSteps) return [];
  const steps = config.nextSteps(ctx);
  const list = Array.isArray(steps) ? steps : [steps];
  return list.filter((s): s is string => typeof s === "string" && s.length > 0);
}
