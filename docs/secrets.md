# Secrets: `@shelbyb/daywalker-sdk/secrets`

Fetch an environment's secrets at runtime with a DevPulse service token (`dps_…`), from `GET {host}/api/v1/secrets`. The token goes only in the `Authorization` header; nothing is cached or written to disk.

```ts
import { fetchSecrets } from "@shelbyb/daywalker-sdk/secrets";

const { secrets, environment, warnings } = await fetchSecrets({ host: process.env.DEVPULSE_URL!, token: process.env.DEVPULSE_SECRETS_TOKEN! });
```

- `fetchSecrets()` returns `{ secrets, environment, warnings }` (warnings list unresolved references).
- `fetchDotenv()` returns dotenv text; `parseDotenv(text)` parses it.
- Errors are `DevPulseHttpError` with `status`: 401 (bad or expired token), 403 (IP not allowed), 429 (`retryAfter`).

## Node: load into `process.env`

A separate entry point so browser and worker bundles never touch `process`:

```ts
import { loadSecrets } from "@shelbyb/daywalker-sdk/secrets/env";

await loadSecrets({ host: process.env.DEVPULSE_URL!, token: process.env.DEVPULSE_SECRETS_TOKEN! }); // existing variables win
```

Pass `override: true` to replace variables already set, or `env` to target another object. Returns `{ loaded, skipped, … }`.
