// Node only: copy secrets into process.env at startup (existing variables win).
import { loadSecrets } from "@shelbyb/daywalker-sdk/secrets/env";

const { loaded, skipped } = await loadSecrets({ host: process.env.DEVPULSE_URL!, token: process.env.DEVPULSE_SECRETS_TOKEN! });
console.log(`loaded ${loaded.length}, kept ${skipped.length} already set`);
