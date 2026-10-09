# @shelbyb/daywalker-sdk

Connect any service to [Daywalker Auth](https://auth.daywalker.dev): validate API tokens and make **domain-signed** API calls that pass token allowlists from any host, CDN, container, or serverless platform.

## Setup (once per service)

```bash
npm install @shelbyb/daywalker-sdk
npx daywalker init --domain myservice.daywalker.dev --service my-service-slug
# On DigitalOcean App Platform, also set the env vars on the live app:
npx daywalker init --domain myservice.daywalker.dev --service my-service-slug --do-app my-app
```

`init`:
- generates an Ed25519 signing key
- adds the `/.well-known/daywalker-keys.json` route (Next.js; for Express it prints the one line to add)
- writes `DAYWALKER_SERVICE_SLUG`, `DAYWALKER_DOMAIN`, and `DAYWALKER_SIGNING_KEY` to `.env.local` (git-ignored)
- with `--do-app`, sets them on your DigitalOcean app through `doctl`, with the key as an encrypted secret

The private key is never printed unless you pass `--print-key`.

Then set `DAYWALKER_API_KEY` to the service's token, deploy, run `npx daywalker check`, and in the Daywalker dashboard click **Connect** on the token to add your domain to its allowed callers.

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `DAYWALKER_API_KEY` | ✅ | The service's Daywalker API token (`srv_live_…`) |
| `DAYWALKER_SERVICE_SLUG` | ✅ | The service slug to validate against. Each service sets its own |
| `DAYWALKER_SIGNING_KEY` | for allowlisted tokens | Ed25519 private key from `daywalker init` (secret) |
| `DAYWALKER_DOMAIN` | recommended | Public hostname that serves the key. Falls back to `APP_URL`, `NEXTAUTH_URL`, `NEXT_PUBLIC_APP_URL`, `BETTER_AUTH_URL`, `PUBLIC_URL`, `SITE_URL`, `URL`, `VERCEL_PROJECT_PRODUCTION_URL`, `RENDER_EXTERNAL_HOSTNAME`, `RAILWAY_PUBLIC_DOMAIN`, `VERCEL_URL` |
| `DAYWALKER_SIGNING_KEY_PREVIOUS` | during rotation | Old key, still published so in-flight requests verify |
| `DAYWALKER_AUTH_URL` | optional | Defaults to `https://auth.daywalker.dev` |

Internal addresses (`0.0.0.0`, `localhost`, IPs) are never used as the domain, so a container's bind address can't end up in a signature.

## Usage

```ts
import { daywalker } from "@shelbyb/daywalker-sdk";

// Validate DAYWALKER_API_KEY for DAYWALKER_SERVICE_SLUG (successful results cached for 60s)
const result = await daywalker().validateToken();
if (!result.valid) console.error(result.status, result.data.message);

// Or validate a token your own users send you
await daywalker().requireValidToken({ token: req.headers["x-api-token"] }); // throws DaywalkerError

// Signed call to any Daywalker Auth API path
const res = await daywalker().fetch("/api/v1/tokens/validate", { body: { token, serviceSlug: "other" } });
```

`result.data` includes `rateLimit` (per minute) and `rateLimitHourly` (per hour), each `{ limit, remaining, reset }`. On a `429`, `result.retryAfter` is the number of seconds to wait.

### Serving the public key

Next.js (App Router), which `init` creates for you:

```ts
// app/.well-known/daywalker-keys.json/route.ts
export { GET, dynamic } from "@shelbyb/daywalker-sdk/next";
```

Express / Connect / Node http:

```ts
import { daywalkerKeys } from "@shelbyb/daywalker-sdk/express";
app.use(daywalkerKeys());
```

Anything else: serve `JSON.stringify(daywalker().keys())` at `GET /.well-known/daywalker-keys.json`. It must be on the domain itself over HTTPS, without redirects.

### Custom clients

```ts
import { createDaywalker } from "@shelbyb/daywalker-sdk";
const client = createDaywalker({ serviceSlug: "gigpulse", domain: "gigpulse.daywalker.dev", cacheTtlMs: 0 });
```

## Commands

| Command | Does |
|---|---|
| `npx daywalker init --domain <host> --service <slug> [--do-app <app>]` | Generate a key, add the key route, write env (re-running keeps the existing key; `--force` replaces it) |
| `npx daywalker check` | Validate config and confirm the domain publishes the current key |
| `npx daywalker rotate [--do-app <app>]` | New key; the old one stays published as `DAYWALKER_SIGNING_KEY_PREVIOUS`. Remove that after the deploy is live |

## How signing works

Each request carries `X-Daywalker-Domain`, `-Key-Id`, `-Timestamp`, `-Nonce`, and `-Signature`, an Ed25519 signature over the method, path, domain, timestamp, nonce, and the body's SHA-256. Daywalker fetches the public key from your domain over HTTPS, so a valid signature proves the request comes from whoever controls the domain. Timestamps must be within 5 minutes and nonces are single-use. See the Daywalker README for the full protocol.
