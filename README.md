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
- **Class-Based Client Architecture**: Instantiable `Daywalker` client supporting dependency injection, with a lazy default singleton for plug-and-play simplicity.
- **Resilience & Rate Limiting**: 5s per-attempt timeout, exponential backoff with jitter, `Retry-After` honored up to 60s. Network errors are retried only for idempotent requests (or with an `idempotencyKey`), and redirects are never followed, so the API key can't leak to another host.
- **Deterministic Type-Safe Results**: Discriminated union returns (`Result<T, E>`) for clean handling without try/catch boilerplate.
- **Security-Hardened Next.js Middleware**: Built-in Server Action probe mitigation (CVE-2025-55182 defense), normalized paths (no `%2e%2e` / `//` bypasses), open-redirect-safe error routing, and fail-closed validation (503 when Daywalker is unreachable).
- **Zero-Egress Inbound Verification**: In-memory caching (60–300s TTL) and offline JWT token lease validation using Daywalker's asymmetric public key.
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

---

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `DAYWALKER_API_KEY` | ✅ | The service's Daywalker API token (`srv_live_…`) or access token |
| `DAYWALKER_SERVICE_SLUG` | ✅ | The service slug to validate against (e.g. `sonalyze`). One API key can cover several services: a comma-separated list (`gigpulse,devpulse`) is accepted and the first is the default. See [One API key, several services](#one-api-key-several-services) |
| `DAYWALKER_SIGNING_KEY` | for signed requests | Ed25519 private key from `daywalker init` (PKCS#8 Base64 DER or PEM) |
| `DAYWALKER_KEY_ID` | optional | RFC 7638 JWK thumbprint derived during key generation |
| `DAYWALKER_SIGNING_KEY_PREVIOUS` | during rotation | Previous private key, maintained during deployment transitions |
| `DAYWALKER_DOMAIN` | optional | Optional caller identifier or host domain name |
| `DAYWALKER_PUBLIC_KEY` | optional | Daywalker Auth public key for zero-egress offline JWT lease verification |
| `DAYWALKER_AUTH_URL` | optional | Defaults to `https://auth.daywalker.dev`; must be `https://` (except localhost) |
| `DAYWALKER_LEASE_ISSUER` | optional | Expected `iss` of offline-verified JWTs (default `https://auth.daywalker.dev`) |

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
// Service health check of this service's own DAYWALKER_API_KEY: daywalker.validateServiceKey()

if (result.ok) {
  console.log("Validated tenant:", result.data.tenantId);
  console.log("Rate limit remaining:", result.data.rateLimit.remaining);
} else {
  // SERVICE_UNAVAILABLE (503) when Daywalker can't be reached: the token is NOT treated as valid.
  console.error(`Validation failed (${result.status} ${result.error}): ${result.message}`);
}
```

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
// Outbound request automatically computes Content-Digest (RFC 9530)
// and attaches RFC 9421 signature headers. Retries 429 rate limits automatically.
const res = await client.fetch("/api/v1/tokens/validate", {
  method: "POST",
  body: { token: "user_token", serviceSlug: "other-service" },
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

Each request must carry `Authorization: Bearer <token>` or `x-api-token`; without one, API routes get `401` and pages redirect to `errorPath` (without an error message in the URL). Paths are decoded and normalized before any check, so `/_next/static/../admin` is authenticated. Only `/_next/static/`, `/_next/image`, `/favicon.ico`, `/robots.txt`, `/sitemap.xml` and the health paths skip auth by default. File extensions say nothing about whether a route is public, so they no longer skip auth; opt in with `staticFileExtensions: STATIC_FILE_EXTENSIONS` if you rely on that. When Daywalker is unreachable the middleware answers `503`, and `500` for a configuration error. To gate the app on this service's own API key instead (the self-healing error page), use `createDaywalkerServiceHealthMiddleware` with the same options.

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
import { daywalkerAuth, daywalkerKeys } from "@shelbyb/daywalker-sdk/express";

const app = express();
app.use(daywalkerKeys()); // serves GET /.well-known/daywalker-keys.json
app.use("/api", daywalkerAuth({ serviceSlug: "sonalyze" }));

app.get("/api/me", (req, res) => res.json({ auth: req.auth }));
```

`daywalkerAuth` reads `Authorization: Bearer <token>` or `x-api-token`, answers `401` when neither is present, and otherwise returns the same status codes as the other middleware (`429` with `Retry-After`, `503` when Daywalker is unreachable). On success the validated payload is on `req.auth`. Both functions also work with plain `http.createServer` handlers.

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

**Client credentials flow (the JWT lists every service).** Your backend authenticates with its client credentials (API key + registered signing key) and gets a short-lived access token (5 to 15 minutes) plus a rotating refresh token. No request names a service; the token lists them:

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

Tokens must have a numeric `exp`, a `jti`, and an `aud` (or `serviceSlug`) containing your service slug, so `serviceSlug` must be configured. A lease that lists `services` must list yours too. `result.data.services` is every service the lease covers (see [One API key, several services](#one-api-key-several-services)). Set `leaseIssuer` (or `DAYWALKER_LEASE_ISSUER`) to also check `iss`.

---

## CLI Reference

| Command | Description |
|---|---|
| `npx daywalker init --service <slug[,slug…]> [--domain <host>] [--api-key-stdin] [--skip-register] [--force] [--json]` | Generate Ed25519 key, register with Daywalker Auth, and write `.env.local` or output JSON |
| `npx daywalker check` | Validate configuration, signature readiness, and connection |
| `npx daywalker rotate [--service <slug[,slug…]>] [--api-key-stdin] [--skip-register] [--json]` | Generate and register a new key while preserving the previous key in `.env.local` |

---

## API Reference (per the [OpenAPI spec](https://auth.daywalker.dev/docs))

| Endpoint | SDK usage | Notes |
|---|---|---|
| `POST /api/v1/tokens/validate` | `client.validateToken()` | Body `{ token, serviceSlug }`; signed with `Signature-Input`, `Signature`, `Content-Digest`. Errors: `400` (`DIGEST_MISMATCH`/missing fields), `401` (`INVALID_SIGNATURE`/invalid token), `403`, `429`. Response includes `valid`, `tokenId`, `tokenName`, `userId`, `stage`, `rateLimit`, `rateLimitHourly` and `X-RateLimit-*` / `X-RateLimit-Hourly-*` headers |
| `POST /api/v1/keys/register` | `npx daywalker init` / `rotate` | Bearer auth; body `{ keyId, domain, publicKey, serviceSlug? }`; `403 service_not_covered` if the key doesn't cover `serviceSlug` |
| `POST /api/v1/oauth/token` | `client.getTokens({ scope?, expiresIn? })`, `client.refreshTokens()`, `client.accessToken()` | `client_credentials` (signed request with mandatory DPoP) and `refresh_token` grants return `{ accessToken, refreshToken, expiresAt, services, … }`; tokens are sender-constrained via DPoP (RFC 9449), refresh tokens rotate, and reuse revokes the session |
| `GET /.well-known/jwks.json` | `client.fetchJwks()` | Daywalker public JWKS for offline lease verification |

Inbound tokens may be supplied as `x-api-token: srv_live_...` or `Authorization: Bearer <JWT or API key>`.

---

## Request Signing Specification (RFC 9421 & RFC 9530)

Each outbound request signed by `@shelbyb/daywalker-sdk` includes:
- `Content-Digest: sha-256=:<base64-encoded-hash>:` (POST/PUT/PATCH, and any request with a body)
- `Signature-Input: sig1=("@method" "@path" "@authority" "content-digest");created=<unix_seconds>;keyid="<kid>";alg="ed25519";nonce="<random>"`. `"@query"` is added after `"@path"` when the URL has a query string; `"content-digest"` is left out only for bodyless GET/HEAD/DELETE/OPTIONS requests.
- `Signature: sig1=:<base64-encoded-signature>:`
- `Authorization: Bearer <DAYWALKER_API_KEY>`

A fresh random `nonce` is generated for every attempt (including retries), so identical requests in the same second still produce unique signatures and never trip replay protection. `validateToken()` also shares one in-flight request between concurrent callers for the same token, and briefly caches failures (`negativeCacheTtlMs`, default 3000ms; 429s and network errors are never cached).

Verification reads the covered components from `Signature-Input`, requires `content-digest` to be covered whenever there is a body, and rejects replays. The default replay cache is per process: with several instances, pass a shared `replayStore` (e.g. Redis `SET NX PX`). The exact signature base and test cases are verified against [`test-vectors/signing-rfc9421.json`](./test-vectors/signing-rfc9421.json).

---

## DevPulse SDKs (one package)

The same package ships the [DevPulse](https://github.com/shelbyb/devpulse) client SDKs as subpath exports. Each subpath is tree-shakeable; `react` and the OpenFeature SDKs are optional peer dependencies used only by their subpaths.

| Import | What it is | Docs |
|---|---|---|
| `@shelbyb/daywalker-sdk/flags` | Feature flags for browsers and JS clients, real-time over SSE | [docs/flags.md](./docs/flags.md) |
| `@shelbyb/daywalker-sdk/flags/node` | Server-side flags with local evaluation and streaming updates | [docs/flags-node.md](./docs/flags-node.md) |
| `@shelbyb/daywalker-sdk/flags/react` | React provider and hooks (SSR bootstrap, no flicker) | [docs/flags-react.md](./docs/flags-react.md) |
| `@shelbyb/daywalker-sdk/flags/engine` | The deterministic evaluation engine (advanced / testing) | — |
| `@shelbyb/daywalker-sdk/openfeature/server`, `/openfeature/web` | OpenFeature providers | [docs/openfeature.md](./docs/openfeature.md) |
| `@shelbyb/daywalker-sdk/analytics` | Product analytics: events, page views, identify, sessions (browser and Node) | [docs/analytics.md](./docs/analytics.md) |

```ts
import { createClient } from "@shelbyb/daywalker-sdk/flags";
import { createAnalytics } from "@shelbyb/daywalker-sdk/analytics";

const flags = createClient(clientSideId, { kind: "user", key: user.id }, { baseUrl: "https://devpulse.example.com" });
const analytics = createAnalytics({ writeKey: "dpa_…", host: "https://devpulse.example.com", flags }); // events carry $feature/<key>
```

---

## Provenance & Releases

Releases are published from GitHub Actions ([`publish.yml`](./.github/workflows/publish.yml)) with [npm trusted publishing](https://docs.npmjs.com/trusted-publishers): npm accepts a short-lived OIDC token from this repository's workflow, so there is no long-lived npm token anywhere. Each version carries a signed [provenance attestation](https://docs.npmjs.com/generating-provenance-statements) linking it to the commit and workflow run that built it. Check it on the npm page, or after installing:

```bash
npm audit signatures
```

To cut a release (maintainers): bump `version` in `package.json`, add a `CHANGELOG.md` entry, merge to `main`, then either push a matching tag (`git tag v0.5.0 && git push origin v0.5.0`) or run the **Publish** workflow from `main` with the version. The workflow refuses tags not on `main`, versions that don't match `package.json`, and versions already on npm. Tests and packing run in a job without the OIDC token; only the final job, which uploads the tested tarball, can publish.

---

## License

MIT
