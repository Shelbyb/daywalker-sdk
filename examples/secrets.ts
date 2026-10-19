// Fetch secrets at runtime with a service token (any runtime). Env: DEVPULSE_URL, DEVPULSE_SECRETS_TOKEN (dps_...).
import { fetchDotenv, fetchSecrets, parseDotenv } from "@shelbyb/daywalker-sdk/secrets";

const { secrets, environment, warnings } = await fetchSecrets({ host: process.env.DEVPULSE_URL!, token: process.env.DEVPULSE_SECRETS_TOKEN! });
if (warnings.length) console.warn(warnings);
console.log(`loaded ${Object.keys(secrets).length} secrets for ${environment}`);

const dotenv = parseDotenv(await fetchDotenv({ host: process.env.DEVPULSE_URL!, token: process.env.DEVPULSE_SECRETS_TOKEN! }));
console.log(Object.keys(dotenv));
