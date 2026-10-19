<p align="center">
  <img src="https://raw.githubusercontent.com/Shelbyb/daywalker-sdk/main/assets/logo-512.png" alt="Daywalker" width="160" />
</p>

# @shelbyb/daywalker-sdk

[![npm](https://img.shields.io/npm/v/@shelbyb/daywalker-sdk)](https://www.npmjs.com/package/@shelbyb/daywalker-sdk)
[![CI](https://github.com/Shelbyb/daywalker-sdk/actions/workflows/ci.yml/badge.svg)](https://github.com/Shelbyb/daywalker-sdk/actions/workflows/ci.yml)
[![license](https://img.shields.io/npm/l/@shelbyb/daywalker-sdk)](./LICENSE)

Runtime-agnostic client library for [Daywalker Auth](https://auth.daywalker.dev). Supports **RFC 9421 (HTTP Message Signatures)**, **RFC 9530 (Digest Fields)**, **Web Crypto standards**, **Push Architecture key registration**, and **hardened web & Next.js middleware**.

Runs on **Node.js 20.19+**, **Bun**, **Deno**, **Cloudflare Workers**, **Next.js Edge**, and browsers. ESM only; `require()` works on Node 20.19+ and 22.12+.

- **Web Standards Core**: standard `crypto.subtle`, `Uint8Array`, `fetch`, `Request`, and `Response`. The one runtime dependency is [`re2js`](https://www.npmjs.com/package/re2js), so flag regex rules run in linear time.
- **RFC 9421 (HTTP Message Signatures)**: Cryptographically binds `@method`, `@path`, `@query` (when the URL has one), `@authority`, and `content-digest` (POST/PUT/PATCH and any request with a body) using Ed25519 signatures (`Signature-Input`, `Signature`).
- **RFC 9530 (Digest Fields)**: Computes standard `Content-Digest: sha-256=:<base64>:` headers for payload integrity.
- **OAuth 2.0 Client Credentials**: Calls to Daywalker Auth carry a short-lived, DPoP-bound (RFC 9449) access token from `POST /api/v1/oauth/token`, refreshed automatically with rotating refresh tokens. The API key is only the client credential for that grant and is never sent anywhere else.
- **Class-Based Client Architecture**: Instantiable `Daywalker` client supporting dependency injection, with a lazy default singleton for plug-and-play simplicity.
- **Resilience & Rate Limiting**: 5s per-attempt timeout, exponential backoff with jitter, `Retry-After` honored up to 60s. Network errors are retried only for idempotent requests (or with an `idempotencyKey`), and redirects are never followed, so credentials and access tokens can't leak to another host.
- **Deterministic Type-Safe Results**: Discriminated union returns (`Result<T, E>`) for clean handling without try/catch boilerplate.
- **Security-Hardened Next.js Middleware**: Built-in Server Action probe mitigation (CVE-2025-55182 defense), normalized paths (no `%2e%2e` / `//` bypasses), open-redirect-safe error routing, and fail-closed validation (503 when Daywalker is unreachable).
- **Zero-Egress Inbound Verification**: In-memory caching (60s by default, never more than 300s) and offline verification of Daywalker access tokens, including the DPoP proof of sender-constrained tokens.
- **Tamper-Resistant by Design**: client state lives in true private fields, config and prototypes are frozen, WebCrypto is captured at load, and every input is bounded and validated. See [Security model](#security-model).
- **Decoupled Push Architecture CLI**: `npx daywalker init --json` registers keys directly via `POST /api/v1/keys/register` with zero runtime reverse-HTTP calls.

---

## Installation

```bash
npm install @shelbyb/daywalker-sdk
```

---

## Setup (once per service)

```bash
# Generate Ed25519 keypair and write .env.local
npx daywalker init --service my-service-slug

# Register the public key with Daywalker Auth (domain is required by the API).
# The API key comes from DAYWALKER_API_KEY, or from stdin so it stays out of shell history:
op read op://vault/daywalker/api-key | npx daywalker init --service my-service-slug --domain app.example.com --api-key-stdin

# Print JSON for Vercel, Fly.io, DigitalOcean, or AWS SSM (nothing written to disk):
DAYWALKER_API_KEY=srv_live_... npx daywalker init --service my-service-slug --domain app.example.com --json
```

`daywalker init`:
- Generates an Ed25519 keypair locally using WebCrypto (`crypto.subtle`)
- Registers the public JWK directly with `POST https://auth.daywalker.dev/api/v1/keys/register` (`Authorization: Bearer <API key>`, body `{ keyId, domain, publicKey, serviceSlug }`; responds `201`, or `403 service_not_covered` when the API key doesn't cover the service)
- Writes `DAYWALKER_SERVICE_SLUG`, `DAYWALKER_KEY_ID`, `DAYWALKER_SIGNING_KEY`, and `DAYWALKER_AUTH_URL` to `.env.local` (atomically, mode `0600`), and only after registration succeeds. `--skip-register` writes without registering.
- `--force` replaces an existing key and keeps the old one as `DAYWALKER_SIGNING_KEY_PREVIOUS`
- No route injectors or public `/.well-known/` endpoints needed

The private key is never printed unless you pass `--print-key`.

### Guided setup: `daywalker onboard`

One command takes a new developer from nothing to a configured service:

```bash
npx daywalker onboard            # interactive
npx daywalker onboard --dry-run  # show the plan; no network calls, no writes
```

Flow: sign up (or log in), verify the email (paste the link or token, or stop and resume later), pick a service from the live list (`GET /api/v1/services`), give the public app URL, create an API token (allowed origins: the app URL plus `https://localhost:3000`), write `DAYWALKER_API_KEY`, then register a signing key exactly as `init` does.

- Flags: `--service <slug>` (skips the menu), `--url <https://app>`, `--name`, `--email`, `--existing-account`, `--dry-run`, `--yes`.
- Non-interactive (`--yes`): the password comes from `DAYWALKER_ONBOARD_PASSWORD` and the emailed token from `DAYWALKER_ONBOARD_VERIFY_TOKEN`. Neither is ever logged or written to disk.
- Progress is saved in a gitignored `.daywalker-onboard.json` (stage, name, email, domain, service; never the password, token or keys), so a stopped run resumes where it left off.
- An existing `DAYWALKER_API_KEY` or project value in `.env.local` is never replaced without confirmation. The file is written atomically with mode `0600`.
- Accounts with MFA can't use this flow; create the token in the dashboard instead.

#### Project extension: `daywalker.onboard.mjs`

A project can add its own prompts and `.env.local` values with an optional file at its root. It is plain JavaScript and needs no SDK import. Because it is executable code, onboarding asks before running it (`--yes` trusts it).

```js
export default {
  defaultService: 'my-service',                 // skips the service menu
  localOrigins: ['https://localhost:3000'],     // allowed on the token, besides the app URL
  env: [
    { key: 'SPOTIFY_CLIENT_ID', label: 'Spotify Client ID', required: true },
    { key: 'SPOTIFY_CLIENT_SECRET', label: 'Spotify Client Secret', required: true, hidden: true },
    { key: 'LASTFM_API_KEY', label: 'Last.fm API key', mirrorTo: ['NEXT_PUBLIC_LASTFM_API_KEY'] },
  ],
  generate: { NEXTAUTH_SECRET: 'base64-48' },   // base64-48 | base64-32 | hex-32; only if unset
  fixed: { NEXTAUTH_URL: 'https://localhost:3000' },
  nextSteps: (ctx) => [`Add the redirect URI for ${ctx.domain}`], // ctx: { slug, domain, localOrigins }
};
```

Values may not contain quotes, `$`, backslashes or control characters, and the hook may not set `DAYWALKER_*` keys. Env values for non-interactive runs are read from the process environment by key.

### Or: ephemeral keys (nothing stored anywhere)

With `ephemeralKey`, each process generates its signing key in memory as a **non-extractable** key. It registers that key with a lifetime and replaces it in place before it expires. There's no private key in env vars, files or a store, and nothing to rotate by hand:

```ts
const client = new Daywalker({
  ephemeralKey: { ttlSeconds: 21_600, instanceId: process.env.HOSTNAME }, // or DAYWALKER_EPHEMERAL_KEY=true
});
process.on("SIGTERM", async () => {
  await client.close(); // revokes the key (and the OAuth sessions it started)
  process.exit(0);
});
```

- **Lifetime** (`ttlSeconds`, env `DAYWALKER_KEY_TTL_SECONDS`): 1 hour to 30 days, default 6 hours. When a quarter of it is left, a new key is registered in the same slot. Requests keep using the old key until the new one is ready, and Daywalker keeps the old key valid for 10 more minutes. The next OAuth session starts with the new key.
- **Slot** (`instanceId`, env `DAYWALKER_INSTANCE_ID`): one key per (domain, slot). Registering in an occupied slot retires the previous key. Default: a random slot per process.
- **Limit:** Daywalker allows 20 live keys per domain. Give long-lived instances a stable `instanceId` so a restart replaces its own key, call `close()` on shutdown, and use a shared `keyStore` instead on serverless platforms with many short-lived instances. When the domain is full, the error says so: list keys with `npx daywalker keys` and revoke unused ones with `npx daywalker revoke <keyId>`.

### Or: provision the key automatically

Instead of running `init` and copying `DAYWALKER_SIGNING_KEY` into every environment, give the client a **key store**. On first use it loads the key from the store, or generates one, registers it for the service's domain (`POST /api/v1/keys/register`, with `DAYWALKER_API_KEY`) and saves it:

```ts
import { Daywalker } from "@shelbyb/daywalker-sdk";
import { fileKeyStore } from "@shelbyb/daywalker-sdk/keystore/file";

const client = new Daywalker({
  keyStore: fileKeyStore(), // .daywalker/signing-key.json (0600, in a 0700 directory)
});
await client.provisionSigningKey(); // optional: provision at startup and fail fast, instead of on the first request
```

All you need is `DAYWALKER_API_KEY` and a domain. The domain is detected from `VERCEL_PROJECT_PRODUCTION_URL`, `RAILWAY_PUBLIC_DOMAIN`, `RENDER_EXTERNAL_HOSTNAME`, `APP_URL` and similar; set `DAYWALKER_DOMAIN` elsewhere.

| Store | Import | Use it for |
|---|---|---|
| `fileKeyStore({ path? })` | `@shelbyb/daywalker-sdk/keystore/file` | VMs and containers with a persistent volume (Node.js). Atomic create-if-absent; refuses symlinks and files others can read |
| `memoryKeyStore()` | `@shelbyb/daywalker-sdk/keystore` | Tests and single long-lived processes: every new process registers a new key |
| `envKeyStore(env?)` | `@shelbyb/daywalker-sdk/keystore` | Read-only: the key `daywalker init` wrote to the environment |
| your own | — | Serverless and several instances: any shared store with an atomic create-if-absent (Redis `SET key value NX`, Vercel / Cloudflare KV, a secrets manager) |

A store is `{ load(), saveIfAbsent?(record) }`. `saveIfAbsent` must be atomic: when several instances start at once, exactly one save wins and the others load the winner's key. Each of them may already have registered its own key; the losers revoke theirs right away (`DELETE /api/v1/keys/{keyId}`). Stored keys don't expire; every key the SDK registers gets its own slot (`dw-<keyId>`), so registering one never retires a key another deployment is still using.

```ts
const redisKeyStore = (redis) => ({
  load: async () => JSON.parse((await redis.get("daywalker:signing-key")) ?? "null"),
  saveIfAbsent: async (record) => (await redis.set("daywalker:signing-key", JSON.stringify(record), { NX: true })) === "OK",
});
```

Safeguards:
- Only keys this process generated **and registered** are ever saved, so a key planted in the store is never registered with your API key.
- A stored key is checked against its `keyId` (RFC 7638 thumbprint) and domain on every load, and imported non-extractable.
- `selfCheck()` / `npx daywalker check --offline` only read the store; they never provision.

Treat the store like any secret: it holds the private key. `DAYWALKER_SIGNING_KEY` and `signer` take precedence over `keyStore`.

### Or: keep the key in a KMS (no private key in the app at all)

Pass a `signer` and the SDK never sees the private key. Every RFC 9421 signature is made by your KMS or HSM. `sign` receives the signature base and must return the raw 64-byte Ed25519 signature:

```ts
const client = new Daywalker({
  signer: {
    keyId: "kms-ed25519-2026-10", // the id you registered the key under
    publicJwk,                    // optional but recommended: the SDK checks the signer against it once before any request
    sign: async (data) => yourKms.signEd25519(KMS_KEY_ID, data), // must resolve to the raw 64-byte signature (Uint8Array)
  },
});
```

Your KMS must support Ed25519 (pure EdDSA over the message, not a pre-hashed variant). Register the KMS public key once with `registerPublicKey({ apiKey, domain, publicJwk })`. The signer is captured at construction, so changing the object later has no effect.

---

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `DAYWALKER_API_KEY` | ✅ | The service's OAuth client credential (`srv_live_…`). It is sent only to `POST /api/v1/oauth/token` (client credentials grant, together with the signing key) and to `POST /api/v1/keys/register` by `daywalker init` / `rotate`. Every other call uses an access token. See [Authentication](#authentication-oauth-20-client-credentials) |
| `DAYWALKER_SERVICE_SLUG` | ✅ | The service slug to validate against (e.g. `sonalyze`). One API key can cover several services: a comma-separated list (`gigpulse,devpulse`) is accepted and the first is the default. See [One API key, several services](#one-api-key-several-services) |
| `DAYWALKER_SIGNING_KEY` | for signed requests | Ed25519 private key from `daywalker init` (PKCS#8 Base64 DER or PEM). Not needed with a `keyStore` (auto-provisioning) or a `signer` (KMS); see [Setup](#setup-once-per-service) |
| `DAYWALKER_KEY_ID` | optional | RFC 7638 JWK thumbprint derived during key generation |
| `DAYWALKER_SIGNING_KEY_PREVIOUS` | during rotation | Previous private key, maintained during deployment transitions |
| `DAYWALKER_DOMAIN` | when not detected | The service's public domain: the key is registered for it. Detected from your platform's URL variables when unset |
| `DAYWALKER_EPHEMERAL_KEY` | optional | `true` for [ephemeral signing keys](#or-ephemeral-keys-nothing-stored-anywhere), with `DAYWALKER_KEY_TTL_SECONDS` and `DAYWALKER_INSTANCE_ID` |
| `DAYWALKER_PUBLIC_KEY` | optional | Daywalker Auth public key for zero-egress offline JWT lease verification |
| `DAYWALKER_JWKS` | optional | `auto` verifies access tokens offline against Daywalker's JWKS, fetched from `${DAYWALKER_AUTH_URL}/.well-known/jwks.json` and cached, so signing-key rotation needs no redeploy. Default `off`. See [Zero-Egress Offline Verification](#zero-egress-offline-verification) |
| `DAYWALKER_AUTH_URL` | optional | Defaults to `https://auth.daywalker.dev`; must be `https://` (except localhost) |
| `DAYWALKER_LEASE_ISSUER` | optional | Expected `iss` of offline-verified JWTs (default `https://auth.daywalker.dev`) |
| `DAYWALKER_PUBLIC_ORIGIN` | behind a proxy | The origin clients use to reach this service (e.g. `https://api.example.com`), for checking DPoP proofs. Defaults to the request URL's origin |

---

## Usage

### Client Class & Instantiation

```ts
import { Daywalker, daywalker } from "@shelbyb/daywalker-sdk";

// Option 1: Instantiable client with custom options / dependency injection
const client = new Daywalker({
  apiKey: process.env.DAYWALKER_API_KEY,
  serviceSlug: "sonalyze",
  maxRetries: 3,
  timeoutMs: 5000, // per attempt (default)
});

// Option 2: Default lazy singleton (reads process.env automatically)
const result = await daywalker.validateToken(incomingToken);
// Service health check of this service's own OAuth client credentials: daywalker.validateServiceCredentials()

if (result.ok) {
  console.log("Validated tenant:", result.data.tenantId);
  console.log("Rate limit remaining:", result.data.rateLimit.remaining);
} else {
  // SERVICE_UNAVAILABLE (503) when Daywalker can't be reached: the token is NOT treated as valid.
  console.error(`Validation failed (${result.status} ${result.error}): ${result.message}`);
}
```

### Authentication (OAuth 2.0 Client Credentials)

The SDK authenticates to Daywalker Auth with the OAuth 2.0 client credentials grant ([RFC 6749 §4.4](https://www.rfc-editor.org/rfc/rfc6749#section-4.4)) described in the [Daywalker API docs](https://auth.daywalker.dev/docs). You don't call it yourself: the first request that needs it runs the flow.

1. **Client credentials grant.** `POST /api/v1/oauth/token` with `grant_type=client_credentials`, authenticated by the API key (`Authorization: Bearer srv_live_…`) **and** an RFC 9421 signature from the registered Ed25519 signing key, from an allowlisted domain or IP. This is the only request that carries the API key.
2. **DPoP-bound tokens.** Every token request carries a DPoP proof ([RFC 9449](https://www.rfc-editor.org/rfc/rfc9449)) from a key the client generates in memory. Daywalker answers with `token_type: "DPoP"`: a 5 to 15 minute EdDSA access token bound to that key (`cnf.jkt`), plus a single-use refresh token (30 day session).
3. **Calls use the access token.** `validateToken()` and `client.fetch()` send `Authorization: DPoP <access_token>` plus a fresh DPoP proof with `ath` (bearer or unbound tokens are refused with `401 DPOP_REQUIRED`).
4. **Refresh.** Within 30 seconds of expiry, or on `401 ACCESS_TOKEN_EXPIRED` (retried once), the client trades the refresh token for a new pair (`grant_type=refresh_token`, no API key, same DPoP key). When the session has ended (`invalid_grant`), it runs the client credentials grant again.

```ts
const client = new Daywalker({
  apiKey: process.env.DAYWALKER_API_KEY,          // client credential, used only at the token endpoint
  signingKey: process.env.DAYWALKER_SIGNING_KEY,  // signs the grant (RFC 9421)
});

await client.validateToken(incomingToken);   // Authorization: DPoP <access token>, obtained on demand
await client.accessToken();                  // the current access token, refreshed as needed
await client.validateServiceCredentials();   // health check: can this service still get a token for its service?
```

If the grant itself fails (revoked API key, unregistered signing key, allowlist mismatch), `validateToken()` returns `503 SERVICE_UNAVAILABLE` with the token endpoint's code in the message, never a `401` for the caller's token; a missing `DAYWALKER_API_KEY` is `500 CONFIGURATION_ERROR`.

### Type-Safe Verification & Error Handling

```ts
import { DaywalkerRateLimitError } from "@shelbyb/daywalker-sdk";

// requireValidToken returns data or throws DaywalkerAuthError / DaywalkerRateLimitError
try {
  const auth = await client.requireValidToken(req.headers.get("x-api-token"));
  console.log("Authenticated service:", auth.serviceSlug);
} catch (err) {
  if (err instanceof DaywalkerRateLimitError) {
    console.warn(`Rate limited. Retry after ${err.retryAfter}s`);
  }
}
```

### RFC 9421 Signed Requests with Automatic Backoff

```ts
// Outbound request automatically adds `Authorization: DPoP <access token>` with a DPoP proof,
// computes Content-Digest (RFC 9530) and attaches RFC 9421 signature headers. Retries 429 rate limits automatically.
const res = await client.fetch("/api/v1/tokens/validate", {
  method: "POST",
  body: { token: "user_token" },
  idempotencyKey: crypto.randomUUID(), // optional: lets a POST be retried after a network error
});
```

---

## Hardened Next.js Middleware (`@shelbyb/daywalker-sdk/next`)

```ts
// proxy.ts (Next.js 16; middleware.ts with `export const middleware = createDaywalkerMiddleware(...)` on 15)
import { createDaywalkerProxy } from "@shelbyb/daywalker-sdk/next";

export const proxy = createDaywalkerProxy({
  serviceSlug: "sonalyze",
  errorPath: "/service-error", // redirect unauthorized web visitors
  validateServerActions: true, // drops malformed CVE-2025-55182 scanner probes
});

export const config = {
  // Keep public files out with the matcher: list what is public, not what isn't.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|robots.txt|images/).*)"],
};
```

Each request must carry `Authorization: Bearer <token>`, `Authorization: DPoP <token>` with its `DPoP` proof header, or `x-api-token`. An `Authorization` header with any other scheme, or a credentials header sent twice, is refused rather than skipped. Without credentials, API routes get `401` and pages redirect to `errorPath` (without an error message in the URL). Paths are decoded and normalized before any check, so `/_next/static/../admin` is authenticated. Only `/_next/static/`, `/_next/image`, `/favicon.ico`, `/robots.txt`, `/sitemap.xml` and the health paths skip auth by default. File extensions say nothing about whether a route is public, so they no longer skip auth; opt in with `staticFileExtensions: STATIC_FILE_EXTENSIONS` if you rely on that. When Daywalker is unreachable the middleware answers `503`, and `500` for a configuration error. To gate the app on this service's own OAuth client credentials instead (the self-healing error page), use `createDaywalkerServiceHealthMiddleware` with the same options.

### Route Handler Wrapper

```ts
// app/api/protected/route.ts
import { withDaywalkerAuth } from "@shelbyb/daywalker-sdk/next";

export const POST = withDaywalkerAuth(async (req, { auth }) => {
  return Response.json({ message: "Hello " + auth.serviceSlug, auth });
});
```

---

## Web Standard & Hono Middleware (`@shelbyb/daywalker-sdk/middleware`)

```ts
import { Hono } from "hono";
import { daywalkerAuth } from "@shelbyb/daywalker-sdk/middleware";

const app = new Hono();
app.use("/api/*", daywalkerAuth());

app.get("/api/me", (c) => {
  const auth = c.get("auth");
  return c.json({ auth });
});
```

---

## Express / Connect / Node `http` (`@shelbyb/daywalker-sdk/express`)

```ts
import express from "express";
import { daywalkerAuth } from "@shelbyb/daywalker-sdk/express";

const app = express();
app.use("/api", daywalkerAuth({ serviceSlug: "sonalyze" }));

app.get("/api/me", (req, res) => res.json({ auth: req.auth }));
```

`daywalkerAuth` reads credentials the same way as the Next middleware, answers `401` when there are none (or they are malformed), and otherwise returns the same status codes as the other middleware (`429` with `Retry-After`, `503` when Daywalker is unreachable). On success the validated payload is on `req.auth`. It also works with plain `http.createServer` handlers.

---

## One API Key, Several Services

A Daywalker API token can cover several services (say `gigpulse` and `devpulse`) and carry one allowlist of domains and IPs, so you manage a single set of client credentials instead of one per service. Ask for the extra services when you create the token in the Daywalker dashboard (**Also cover these services**), or with `additionalServiceIds` on `POST /api/v1/tokens` and `PATCH /api/v1/tokens/:id`.

**Each app keeps its own service slug, with the same API key.** Every app (domain) generates and registers its own signing key:

```bash
# gigpulse app
DAYWALKER_API_KEY=srv_live_… npx daywalker init --service gigpulse --domain gigpulse.daywalker.dev
# devpulse app, same API key
DAYWALKER_API_KEY=srv_live_… npx daywalker init --service devpulse --domain devpulse.daywalker.dev
```

`init` and `rotate` take no service: the API key decides which services your credentials cover (`--service` is optional and only sets the audience for offline verification, `DAYWALKER_SERVICE_SLUG`).

**Client credentials flow (the JWT lists every service).** Your backend authenticates with its client credentials (API key + registered signing key, see [Authentication](#authentication-oauth-20-client-credentials)) and gets a short-lived access token (5 to 15 minutes) plus a rotating refresh token. No request names a service; the token lists them:

```ts
const tokens = await client.getTokens();
tokens.services; // ["gigpulse", "devpulse"]; also the JWT's `services` and `aud` claims

// Least privilege: only what this process needs (403 SERVICE_NOT_GRANTED for a service the key doesn't cover)
await client.getTokens({ scope: ["devpulse"], expiresIn: 600 });

// Always-fresh access token: refreshes (and re-authenticates if the session ended) automatically
const accessToken = await client.accessToken();
```

**Refresh token rotation.** `client.refreshTokens()` swaps the refresh token for a *new* access token and a *new* refresh token; the old one stops working. Daywalker keeps each session's refresh tokens as a family: presenting an old one again is treated as theft and revokes the whole family, so your client has to start over with its credentials. `accessToken()` serializes refreshes so concurrent requests never present the same token twice. Don't refresh from several processes with one session.

**The access token** is an EdDSA JWT (RFC 9068, `typ: at+jwt`) with `iss`, `aud`, `jti`, `iat`, `nbf`, `exp`, `services`, and a `user` object: the user's public UUID v7 `id`, `name` and `email`. Read it with `accessTokenUser(payload)` **after** verifying:

```ts
import { verifyJwtLease, accessTokenUser } from "@shelbyb/daywalker-sdk";
const res = await verifyJwtLease({ token, publicKey: jwks, expectedServiceSlug: "devpulse", expectedIssuer: "https://auth.daywalker.dev" });
if (res.valid) accessTokenUser(res.payload!); // { id: "018f…", name: "Ada", email: "ada@example.com" }
```

Verification is strict: only `EdDSA` (never `none` or HMAC, so no algorithm confusion), canonical base64url, `typ` `at+jwt`, issuer, your audience, required `jti` and `exp`, and at most 30 seconds of clock skew. Never decode a token without verifying it.

**Web apps: HttpOnly cookies.** Keep tokens on your server. If the browser must hold them, send them from your backend in cookies scripts can't read:

```ts
import { daywalkerCookies, clearTokenCookie } from "@shelbyb/daywalker-sdk";
const tokens = await client.getTokens();
const res = new Response("ok");
for (const c of daywalkerCookies(tokens, { refreshPath: "/api/auth/refresh" })) res.headers.append("Set-Cookie", c);
// HttpOnly; Secure; SameSite=Strict. The refresh token cookie is only sent to /api/auth/refresh.
```

Services that are inactive, in `DRAFT`, `TESTING` (unless an admin owns the token), or no longer entitled to the token's owner are left out. Check `tokens.services` rather than assuming.

Whoever receives the access token verifies it for **their own** service. It only passes when that slug is in the token's `services` and `aud`:

```ts
const verifier = new Daywalker({ serviceSlug: "devpulse", daywalkerPublicKey: process.env.DAYWALKER_PUBLIC_KEY });
const result = await verifier.validateToken(incomingJwt);
if (result.ok) result.data.services; // ["gigpulse", "devpulse"]: everything this token covers
```

Online validation of an `srv_live_…` token reports the same list in `result.data.services` (a server that predates multi-service tokens yields just the validated slug).

---

## Zero-Egress Offline Verification

When high-throughput internal microservices need zero latency and zero external egress, Daywalker Auth can issue asymmetric JWT leases. Configure `DAYWALKER_PUBLIC_KEY` (PEM or standard JWK) and token validation runs entirely in memory without network calls:

```ts
import { Daywalker } from "@shelbyb/daywalker-sdk";

const client = new Daywalker({
  serviceSlug: "myservice",
  daywalkerPublicKey: process.env.DAYWALKER_PUBLIC_KEY,
});

// Verifies JWT signature, expiration, and service claims locally
const result = await client.validateToken(incomingJwt);
```

### Surviving Daywalker key rotation (`jwks: "auto"`)

A static `DAYWALKER_PUBLIC_KEY` stops verifying the moment Daywalker rotates its signing key. Set `DAYWALKER_JWKS=auto` (or `jwks: "auto"`) and the client verifies against Daywalker's published key set instead:

```ts
const client = new Daywalker({ serviceSlug: "myservice", jwks: "auto" });
```

- The set is fetched from `${authUrl}/.well-known/jwks.json` and nowhere else: a `jwks_uri` in a token response or in the set itself is never followed. The fetch sends no credentials, follows no redirects, bypasses HTTP caches, is capped at 1 MiB and times out after `timeoutMs`.
- Only Ed25519 signing keys for EdDSA with a `kid` are kept (`kty: OKP`, `crv: Ed25519`, `alg` absent or `EdDSA`, `use` absent or `sig`, no private part), at most 16. Everything else in the set is ignored.
- The set is cached in the client for 10 minutes (`JWKS_CACHE_TTL_MS`). A token naming a `kid` the set doesn't have (a rotation) triggers a refetch, but fetches are never closer than 30 seconds apart (`JWKS_REFETCH_COOLDOWN_MS`), whatever triggers them, so tokens with made-up `kid`s can't make the client hammer Daywalker. Concurrent callers share one fetch.
- A failed refresh (outage, redirect, non-JSON, no usable key) keeps the last good set.
- Fail closed: while no set has ever been obtained, the static `daywalkerPublicKey` is used if one is configured; otherwise `offlineOnly` validation returns `503 SERVICE_UNAVAILABLE` and normal validation goes online (`POST /api/v1/tokens/validate`).

Without `jwks: "auto"`, offline verification uses `daywalkerPublicKey` exactly as before.

Tokens must be RFC 9068 access tokens (`typ: at+jwt`, `alg: EdDSA`) with a numeric `exp`, a `jti`, and an `aud` containing your service slug, so `serviceSlug` must be configured. A token that lists `services` must list yours too. A DPoP-bound token (`cnf.jkt`) is only accepted with `Authorization: DPoP` and a valid proof: right method and URL, signed by the bound key, fresh, carrying the token's hash, and never used before. A copied token alone is useless. With several instances, pass a shared `dpopReplayStore` (like `replayStore` for signatures). `result.data.services` is every service the lease covers (see [One API key, several services](#one-api-key-several-services)). Set `leaseIssuer` (or `DAYWALKER_LEASE_ISSUER`) to also check `iss`.

---

## Service License & Config Bundle

Daywalker issues each service a license key with the client credentials grant: derived per service, signing key and one-hour window, never returned for a revoked or suspended service.

```ts
const { licenseKey, expiresAt } = await client.getLicense();   // cached until a minute before expiry
const bundle = await client.fetchBundle();                     // { dataKeySalt, features, issuedAt, expiresAt, ... }
```

`fetchBundle()` downloads a bundle sealed (AES-256-GCM) under the license key and opens it locally, so only a client that got the license from Daywalker can read it. Derive app secrets from `licenseKey` + `bundle.dataKeySalt` (HKDF) so removing the SDK breaks the app. Errors are `DaywalkerAuthError`s: `SERVICE_REVOKED`, `SERVICE_SUSPENDED`, `DOMAIN_REVOKED`, `DOMAIN_MISMATCH`, `LICENSE_UNAVAILABLE`, `BUNDLE_UNREADABLE`. Never log the key.

## CLI Reference

| Command | Description |
|---|---|
| `npx daywalker init --service <slug[,slug…]> [--domain <host>] [--api-key-stdin] [--skip-register] [--force] [--json]` | Generate Ed25519 key, register with Daywalker Auth, and write `.env.local` or output JSON |
| `npx daywalker check [--offline]` | Validate configuration and signature readiness, then run the OAuth client credentials grant to confirm the credentials work and cover the configured service(s) (`--offline` skips that) |
| `npx daywalker rotate [--service <slug[,slug…]>] [--api-key-stdin] [--skip-register] [--json]` | Generate and register a new key while preserving the previous key in `.env.local`. The previous key stays registered until you revoke it, so running deployments keep working |
| `npx daywalker keys [--domain <host>] [--json]` | List the domain's signing keys: status, slot, expiry, last use, and which one is current or previous |
| `npx daywalker revoke <keyId> [--force]` | Revoke a key now; Daywalker also ends the OAuth sessions it started. Refuses the current `DAYWALKER_KEY_ID` unless `--force` |
| `npx daywalker license apply\|check [--dir <path>] [--governing-law <text>] [--dry-run]` | Install or verify the DevPulse source-available license in a project: `LICENSE`, `package.json` fields, README section, notice headers on files that use the SDK, and the boot log line ([docs/license.md](./docs/license.md)) |

---

## API Reference (per the [OpenAPI spec](https://auth.daywalker.dev/docs))

| Endpoint | SDK usage | Notes |
|---|---|---|
| `POST /api/v1/tokens/validate` | `client.validateToken()` | `Authorization: DPoP <access_token>` + `DPoP` proof; body `{ token }`; signed with `Signature-Input`, `Signature`, `Content-Digest`. Errors: `400` (`DIGEST_MISMATCH`/missing fields), `401` (`INVALID_SIGNATURE`, `DPOP_REQUIRED`, `INVALID_DPOP_PROOF`, `DPOP_REPLAY`, `ACCESS_TOKEN_EXPIRED`, invalid token), `403` (`SERVICE_NOT_GRANTED`, allowlist), `429`. Response includes `valid`, `tokenId`, `tokenName`, `userId`, `stage`, `rateLimit`, `rateLimitHourly` and `X-RateLimit-*` / `X-RateLimit-Hourly-*` headers |
| `POST /api/v1/keys/register` | `registerPublicKey()`, `npx daywalker init` / `rotate`, `keyStore` / `ephemeralKey` provisioning | `Authorization: Bearer <API key>` (bootstraps the signing key the client credentials grant needs); body `{ keyId, domain, publicKey, serviceSlug?, instanceId?, ttlSeconds?, expiresAt? }`. `200` re-registration (idempotent), `201` new; `409 KEY_LIMIT_REACHED` (20 live keys per domain) or `KEY_ID_CONFLICT`; `403 domain_not_allowed`. The SDK always passes an `instanceId`, because without one Daywalker retires every other slot-less key of the domain after 10 minutes |
| `GET /api/v1/keys?domain=` | `listSigningKeys()`, `npx daywalker keys` | The domain's keys with `status`, `instanceId`, `expiresAt`, `lastUsedAt` |
| `DELETE /api/v1/keys/{keyId}` | `revokeSigningKey()`, `client.close()`, `npx daywalker revoke` | Revokes now and ends the OAuth sessions started with the key |
| `POST /api/v1/oauth/token` | `client.getTokens({ scope?, expiresIn? })`, `client.refreshTokens()`, `client.accessToken()` (called for you by `validateToken()` / `fetch()`) | `client_credentials` (API key as Bearer + signed request, mandatory DPoP) and `refresh_token` grants return `{ accessToken, refreshToken, expiresAt, services, … }`; tokens are sender-constrained via DPoP (RFC 9449), refresh tokens rotate, and reuse revokes the session |
| `GET /.well-known/jwks.json` | `client.fetchJwks()` | Daywalker public JWKS for offline lease verification |

Inbound tokens may be supplied as `x-api-token: srv_live_...`, `Authorization: Bearer <token>`, or `Authorization: DPoP <access token>` with a `DPoP` proof. An online answer must name your service: a token validated for a sibling service your credentials also cover is refused with `403 SERVICE_NOT_GRANTED`.

---

## Request Signing Specification (RFC 9421 & RFC 9530)

Each outbound request signed by `@shelbyb/daywalker-sdk` includes:
- `Content-Digest: sha-256=:<base64-encoded-hash>:` (POST/PUT/PATCH, and any request with a body)
- `Signature-Input: sig1=("@method" "@path" "@authority" "content-digest");created=<unix_seconds>;keyid="<kid>";alg="ed25519";nonce="<random>"`. `"@query"` is added after `"@path"` when the URL has a query string; `"content-digest"` is left out only for bodyless GET/HEAD/DELETE/OPTIONS requests.
- `Signature: sig1=:<base64-encoded-signature>:`
- `Authorization: DPoP <access_token>` and `DPoP: <proof JWT>` (`htm`, `htu`, `iat`, `jti`, `ath`). Only the client credentials grant on `/api/v1/oauth/token` sends `Authorization: Bearer <DAYWALKER_API_KEY>` instead.

A fresh random `nonce` is generated for every attempt (including retries), so identical requests in the same second still produce unique signatures and never trip replay protection. `validateToken()` also shares one in-flight request between concurrent callers for the same token, and briefly caches failures (`negativeCacheTtlMs`, default 3000ms; 429s and network errors are never cached).

Verification reads the covered components from `Signature-Input`, requires `content-digest` to be covered whenever there is a body, and rejects replays. The default replay cache is per process: with several instances, pass a shared `replayStore` (e.g. Redis `SET NX PX`). The exact signature base and test cases are verified against [`test-vectors/signing-rfc9421.json`](./test-vectors/signing-rfc9421.json).

---

## Security Model

This SDK checks that callers hold a valid Daywalker credential, and that the service it runs in holds valid OAuth client credentials. It is built to resist tampering by **other code in the same process** (a compromised dependency, an injected script, a confused AI agent editing at runtime):

- **No reachable internals.** Caches, tokens, the DPoP key and the config are ES `#private` fields, so `client._cache` doesn't exist to be poisoned. `Daywalker.prototype`, the class and each instance are frozen, so `validateToken` can't be swapped by assignment, including on the shared `daywalker` client.
- **Frozen, secret-free config.** `client.config` is frozen and shows the API key and private keys only as `"[configured]"`. The options object is read once, so changing it later (say, `authUrl` or `fetch`) has no effect.
- **Captured primitives.** WebCrypto (`subtle.verify`, `sign`, `digest`, …) is captured when the SDK loads, so replacing `crypto.subtle.verify` later can't make forged tokens verify. The Next adapter builds its own responses and ignores any `NextResponse` planted on `globalThis`.
- **Sender-constrained tokens.** The SDK's own access tokens are DPoP-bound to a non-extractable key generated in memory, and only the token endpoint ever sees the API key. Incoming DPoP-bound tokens need a valid proof.
- **Bounded, validated input.** Tokens (≤ 8 KiB, token characters only), headers, DPoP proofs, JWTs and response bodies (≤ 1 MiB) are size-checked and validated before use. Nothing is followed through a redirect, cached by an HTTP cache (`cache: "no-store"`), or trusted from an answer of the wrong shape (fail closed).

**What no client-side SDK can do:** stop the operator of the server it runs on. Whoever controls a deployment can edit `node_modules`, patch the code, or delete the middleware, and obfuscation only slows that down. So treat this package as the *enforcement point*, and put the *decision* on Daywalker's side, where it can't be removed:

1. Make the service depend on what only a valid grant provides. Read limits and features from the verified access token (`service_limits`, `service_features`) rather than from local config, so code with the SDK ripped out has nothing to run on.
2. Revoke on Daywalker. Revoking the API key, signing key or allowlist entry ends the client credentials session (and every refresh) at the next token request, within 15 minutes at most.
3. Keep the signing key and API key in a secret manager, run `npx daywalker check` in CI and at startup, and watch Daywalker's usage analytics for clients that stop calling in.

## DevPulse SDKs (one package)

The same package ships the [DevPulse](https://github.com/shelbyb/devpulse) client SDKs as subpath exports. Each subpath is tree-shakeable; `react` and the OpenFeature SDKs are optional peer dependencies used only by their subpaths.

| Import | What it is | Docs |
|---|---|---|
| `@shelbyb/daywalker-sdk/flags` | Feature flags for browsers and JS clients, real-time over SSE | [docs/flags.md](./docs/flags.md) |
| `@shelbyb/daywalker-sdk/flags/node` | Server-side flags with local evaluation and streaming updates | [docs/flags-node.md](./docs/flags-node.md) |
| `@shelbyb/daywalker-sdk/flags/react` | React provider and hooks (SSR bootstrap, no flicker) | [docs/flags-react.md](./docs/flags-react.md) |
| `@shelbyb/daywalker-sdk/flags/engine` | The deterministic evaluation engine (advanced / testing) | — |
| `@shelbyb/daywalker-sdk/openfeature/server`, `/openfeature/web` | OpenFeature providers | [docs/openfeature.md](./docs/openfeature.md) |
| `@shelbyb/daywalker-sdk/analytics` | Product analytics: events, page views, identify, sessions (browser and Node), plus `captureWebVitals()` | [docs/analytics.md](./docs/analytics.md) |
| `@shelbyb/daywalker-sdk/api` | Typed management REST API client: OAuth client credentials, RFC 9457 errors, Link pagination, retries | [docs/api-client.md](./docs/api-client.md) |
| `@shelbyb/daywalker-sdk/webhooks` | Verify DevPulse webhooks (Standard Webhooks signatures, typed events) | [docs/webhooks.md](./docs/webhooks.md) |
| `@shelbyb/daywalker-sdk/cron` | Cron check pings: start, success, fail, log, exit code, `wrap(fn)` | [docs/cron.md](./docs/cron.md) |
| `@shelbyb/daywalker-sdk/logs` | Batched structured log shipping, console and pino adapters | [docs/logs.md](./docs/logs.md) |
| `@shelbyb/daywalker-sdk/secrets`, `/secrets/env` | Runtime secrets fetch with a `dps_` service token; Node `process.env` loader | [docs/secrets.md](./docs/secrets.md) |
| `@shelbyb/daywalker-sdk/oncall` | On-call Events API v2: trigger, acknowledge, resolve | [docs/oncall.md](./docs/oncall.md) |
| `@shelbyb/daywalker-sdk/slo`, `/deploys` | Push SLO good/total events; record deploy markers | [docs/slo-deploys.md](./docs/slo-deploys.md) |

Runnable, type-checked examples for every import above (and the Daywalker auth entry points) are in [`examples/`](./examples/README.md).

The flags, analytics, API, webhooks, cron, logs, secrets, on-call, SLO and deploys entry points run unchanged in browsers, Node, Deno, Bun and Cloudflare Workers ([docs/runtimes.md](./docs/runtimes.md)). Writing an SDK for another language? See the wire contract in [docs/protocol.md](./docs/protocol.md) and the JSON conformance vectors in `test-vectors/`.

```ts
import { createClient } from "@shelbyb/daywalker-sdk/flags";
import { createAnalytics } from "@shelbyb/daywalker-sdk/analytics";

const flags = createClient(clientSideId, { kind: "user", key: user.id }, { baseUrl: "https://devpulse.example.com" });
const analytics = createAnalytics({ writeKey: "dpa_…", host: "https://devpulse.example.com", flags }); // events carry $feature/<key>
analytics.captureWebVitals({ release: "1.4.2", environment: "production" }); // LCP, INP, CLS, FCP, TTFB to /a/rum
```

### Web Vitals

The analytics client can report real-user performance to DevPulse's **Web Vitals** dashboard: **LCP**, **CLS** (largest session window), **INP** (event timing), **FCP**, **TTFB** and page load, measured with `PerformanceObserver` and navigation timing. Metrics are sent to `POST {host}/a/rum` with your analytics write key, using `navigator.sendBeacon` (falling back to `fetch` with `keepalive`) when the page is hidden or unloaded. CLS and INP are re-sent if they grow; a back/forward-cache restore starts a new page view.

```ts
import { createAnalytics } from "@shelbyb/daywalker-sdk/analytics";

const analytics = createAnalytics({
  writeKey: "dpa_…",
  host: "https://devpulse.example.com",
  autocaptureWebVitals: { sampleRate: 0.5, release: "1.4.2", environment: "production" },
});
// or start it yourself; the returned function stops measuring
const stop = analytics.captureWebVitals({ sampleRate: 0.5 });
```

| Option | Default | Meaning |
|---|---|---|
| `sampleRate` | `1` | Share of page views to measure (0 to 1), decided once per page view |
| `release` | none | Release or version string (`[A-Za-z0-9_.+@/:~-]`, up to 100 characters) |
| `environment` | none | e.g. `production` (`[A-Za-z0-9_.-]`, up to 64 characters) |
| `path` | `location.pathname` | Report this page instead, e.g. a route pattern like `/users/:id` |

**Privacy.** Nothing is measured when Do Not Track or Global Privacy Control is on, and nothing is sent while the client is opted out (`optedOut`, `optOut()`); metrics held back are sent after `optIn()`. Only the page path is sent (never the query string or fragment, and your `sanitizePath` applies), the server collapses ids in paths, and no cookies or storage are used. It does nothing outside browsers or where `PerformanceObserver` is missing. See the [DevPulse Web Vitals docs](https://github.com/Shelbyb/DevPulse/blob/main/docs/RUM.md) for the payload, ratings and dashboard.

---

## Provenance & Releases

Releases are published from GitHub Actions ([`publish.yml`](./.github/workflows/publish.yml)) with [npm trusted publishing](https://docs.npmjs.com/trusted-publishers): npm accepts a short-lived OIDC token from this repository's workflow, so there is no long-lived npm token anywhere. Each version carries a signed [provenance attestation](https://docs.npmjs.com/generating-provenance-statements) linking it to the commit and workflow run that built it. Check it on the npm page, or after installing:

```bash
npm audit signatures
```

To cut a release (maintainers): bump `version` in `package.json`, add a `CHANGELOG.md` entry, merge to `main`, then either push a matching tag (`git tag v0.5.0 && git push origin v0.5.0`) or run the **Publish** workflow from `main` with the version. The workflow refuses tags not on `main`, versions that don't match `package.json`, and versions already on npm. Tests and packing run in a job without the OIDC token; only the final job, which uploads the tested tarball, can publish.

---

## License

Proprietary and Confidential. See [LICENSE](./LICENSE) for terms.

## Token management, DPoP and local verification helpers

```ts
import { createManagementClient, verifyAccessToken, unsealBundle, createDpopProof, generateDpopKey } from "@shelbyb/daywalker-sdk";

// Token CRUD, usage logs and key management authenticate with a user session JWT (not an API key).
const mgmt = createManagementClient({ authUrl: "https://auth.daywalker.dev", sessionToken: () => getSessionJwt() });
await mgmt.createToken({ name: "ci", serviceId, additionalServiceIds: [other], allowedOrigins: ["https://app.example.com"], expiresAt: new Date(Date.now() + 864e5) });
await mgmt.listTokens(); await mgmt.getTokenLogs(id); await mgmt.revokeToken(id);

// Local access token verification (EdDSA, aud, typ at+jwt) with typed `services` / `service_limits`.
const r = await verifyAccessToken({ token, serviceSlug: "my-service", jwks: await daywalker.fetchJwks() });

// DPoP proof for direct calls, and unsealing a bundle with the derived licenseKey.
const proof = await createDpopProof(await generateDpopKey(), { method: "GET", url, accessToken });
const bundle = await unsealBundle(licenseKey, sealed, "my-service");
```
Signing helpers (`signRequest`) and key calls (`registerPublicKey`, `listSigningKeys`, `revokeSigningKey`) are exported from the root too. Python, Go and Ruby SDKs are not included yet.
