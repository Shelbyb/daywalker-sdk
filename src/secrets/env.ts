import { fetchSecrets, type SecretsOptions, type SecretsResult } from "./index.js";

/**
 * Copy DevPulse secrets into an environment object (Node's `process.env` by default). Kept apart
 * from `@shelbyb/daywalker-sdk/secrets` so browser and worker bundles never touch `process`.
 * Existing variables win unless `override` is true.
 */
export type LoadSecretsOptions = SecretsOptions & {
  /** Replace variables that are already set. Default false. */
  override?: boolean;
  /** Target object. Default `process.env`. */
  env?: Record<string, string | undefined>;
};

export type LoadSecretsResult = SecretsResult & {
  /** Keys written to the environment. */
  loaded: string[];
  /** Keys left alone because they were already set. */
  skipped: string[];
};

export async function loadSecrets(options: LoadSecretsOptions): Promise<LoadSecretsResult> {
  const env = options.env ?? (globalThis as { process?: { env: Record<string, string | undefined> } }).process?.env;
  if (!env) throw new Error("No environment object: pass `env`, or use fetchSecrets() outside Node");
  const result = await fetchSecrets(options);
  const loaded: string[] = [];
  const skipped: string[] = [];
  for (const [k, v] of Object.entries(result.secrets)) {
    // `__proto__` would hit the prototype setter of a plain `env` object; inherited members
    // (toString, constructor…) are not "already set" variables.
    const set = Object.prototype.hasOwnProperty.call(env, k) && env[k] !== undefined;
    if (k === "__proto__" || (!options.override && set)) skipped.push(k);
    else {
      env[k] = v;
      loaded.push(k);
    }
  }
  return { ...result, loaded, skipped };
}
