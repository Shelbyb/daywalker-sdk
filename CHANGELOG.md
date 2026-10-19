# Changelog

## 0.16.2
- **`daywalker license apply` no longer relicenses packages or reformats `package.json`.** A package that already declares its own `"license"` (for example an MIT CLI in the same monorepo) is left alone and listed, unless `--replace-existing`; `check` reports such packages as a note instead of a failure. The `license` line is inserted as text, so indentation, inline arrays and key order are preserved.

## 0.16.1
- `daywalker license apply|check --exclude <glob,…>`: leave files alone (for example UI files that only show SDK snippets, or an integrity script), so `check` doesn't flag them either.

## 0.16.0
- **`daywalker license apply|check`:** installs and verifies the DevPulse source-available license in a project: `LICENSE`, `"license": "SEE LICENSE IN LICENSE"` in `package.json` (root and workspaces; `"private"` is never changed), a README section, a notice header on every file that imports the SDK or calls its guards, and the boot log line (added to Next.js `instrumentation.ts` when present). Idempotent, `--dry-run`, and `check` exits non-zero for CI. Comments and metadata only; it never edits code that calls the SDK. See `docs/license.md`.
- The bundled license text is a reviewed redraft (defined terms, no circumvention, tiers, redistribution, patents, trademarks, termination with cure); governing law is an owner decision (`--governing-law`).
- A Claude Code skill, `skills/apply-license`, drives the command and handles the build/Docker steps it only lists.

## 0.15.0
- **Licensing and CLA updates:** Updated project license to a proprietary SDK license (`UNLICENSED` in `package.json`) and added `CONTRIBUTING.md` outlining the Contributor License Agreement (CLA) terms and contribution guidelines.

## 0.14.0
- **Multi-language signed token validation examples:** added runnable Python, Go, and Ruby examples under `examples/` demonstrating how to validate Daywalker signed tokens across languages without the TypeScript SDK.

## 0.13.0
- **New DevPulse clients**, all fetch/WebCrypto only (Node, Deno, Bun, Workers, browsers where it makes sense), HTTPS-only except localhost, credentials only in headers or bodies, redirects refused, sizes capped to DevPulse's limits:
  - `/webhooks`: `verifyWebhook()` for Standard Webhooks signatures (`whsec_` secrets, 5 minute tolerance, constant-time compare, multiple signatures, secret rotation), typed `WebhookEvent`, `signWebhook()`, `isEventType()`. Conformance vectors in `test-vectors/webhooks-standard.json`.
  - `/cron`: `createCronMonitor({ pingUrl })` with `start`/`success`/`fail`/`log`/`exitCode` and `wrap(fn)`; bodies capped at 10,000 characters; pings never throw.
  - `/logs`: `createLogger()` with levels, attributes, child loggers, batching, retries, `flush()`/`shutdown()`, DevPulse size limits, `consoleAdapter()` and `pinoDestination()`.
  - `/secrets`: `fetchSecrets()`, `fetchDotenv()`, `parseDotenv()` with `dps_` service tokens; `/secrets/env`: `loadSecrets()` into `process.env` (existing values win).
  - `/oncall`: Events API v2 `trigger`/`acknowledge`/`resolve` with dedup keys.
  - `/slo`: `createSloReporter()` (per-minute aggregation, each batch sent once since events are not idempotent) and `pushSloEvents()`; `/deploys`: `recordDeploy()`. Both use the `/api` client.
- **Examples:** `examples/` has a type-checked example for every subpath export; `npm run check:examples` compiles them (CI step), and a test fails when an export has no example.
- `test:coverage` now also covers the new modules (90% threshold). `test/runtime-compat.test.ts` covers the new entry points.
- No new runtime dependencies. Existing behavior is unchanged.

## 0.11.0
- Analytics client: Web Vitals capture. New `analytics.captureWebVitals(options?)` (returns a stop function) and `autocaptureWebVitals` constructor option measure LCP, CLS (session windows), INP, FCP, TTFB and page load and send them to DevPulse's `POST {host}/a/rum` with `sendBeacon` (fetch `keepalive` fallback) on page hide. Options: `sampleRate`, `release`, `environment`, `path`. Respects `optedOut`/`optOut()`, Do Not Track and Global Privacy Control; no-op outside browsers or without `PerformanceObserver`.
- New exported types `WebVitalsOptions`, `WebVitalMetric`, `WebVitalEvent`, `WebVitalsPayload`.
- New `npm run test:coverage` (node's built-in coverage, 90% lines/branches/functions threshold on `src/analytics/web-vitals.ts`), now a CI step.
- No new runtime dependencies. Existing behavior is unchanged.

## 0.12.0
- **Management API client:** new `@shelbyb/daywalker-sdk/api` (`createApiClient`): OAuth 2.0 client credentials with cached, early-refreshed tokens, bearer requests, typed RFC 9457 `ApiProblemError`, `paginate()`/`pages()` over RFC 8288 `Link rel="next"` (never to another origin), retries on 429/503 honoring `Retry-After`, `If-Match`/ETag, IETF RateLimit parsing. HTTPS-only (except localhost); credentials never appear in URLs.
- **Runtimes:** `/flags/node` no longer imports `node:crypto` or `node:events` (pure JavaScript SHA-256/HMAC and a small event emitter, same API), and the flags, analytics and API entry points no longer pull in the Daywalker auth module, so they work on Deno, Bun, Cloudflare Workers and browsers. New `./package.json` export. A test fails if a portable entry point imports a Node built-in.
- **Docs and vectors:** `docs/protocol.md` (language-neutral wire contract), `docs/web-vitals.md`, `docs/api-client.md`, `docs/runtimes.md`; new conformance vectors `test-vectors/flags-bucketing.json`, `flags-context.json`, `flags-operators.json` and `secure-mode-hash.json` next to `flags-eval.json`.

## 0.10.0
- New `daywalker onboard` command: sign up or log in, verify the email, choose a service from the live `GET /api/v1/services` list, give the public app URL, create an API token (allowed origins: the URL plus the project's local origins, default `https://localhost:3000`), and register a signing key in-process (same as `init`). Resumable through a gitignored `.daywalker-onboard.json` that never holds the password, token or keys. Flags: `--service`, `--url`, `--name`, `--email`, `--existing-account`, `--dry-run`, `--yes`.
- Optional project extension `daywalker.onboard.mjs` (confirmation required, `--yes` trusts it): extra env prompts, generated and fixed values, `mirrorTo`, `localOrigins`, `defaultService` and `nextSteps`. `DAYWALKER_*` keys are reserved, and values go through the same safety check as `.env.local` writes.
- No new runtime dependencies. Existing commands are unchanged.

## 0.9.1
- `fetchBundle()` errors now name the request and HTTP status (`Bundle request for <slug> failed (HTTP 401): ...`) and always carry a code: the service's `code`/`error`, otherwise derived from the status (`INVALID_TOKEN`, `FORBIDDEN`, `SERVICE_NOT_FOUND`, `RATE_LIMITED`, `SERVICE_UNAVAILABLE`, `BUNDLE_REQUEST_FAILED`).

## 0.9.0
**Per-service license keys, sealed config bundle, and tamper resistance.** Adds technical enforcement ensuring consumer apps cannot bypass Daywalker verification without breaking functionality.
- `client.getLicense({ serviceSlug?, forceRefresh? })`: returns `{ serviceSlug, licenseKey, expiresAt }`. The derived key is computed as HKDF-SHA256(serviceSecret, salt = serviceSlug + keyId + hourWindow, info = "daywalker-license-v1") and cached in memory until shortly before expiry.
- `client.fetchBundle({ serviceSlug?, forceRefresh? })`: returns decrypted JSON config bundle (`{ serviceSlug, dataKeySalt, features, issuedAt, expiresAt }`) sealed with AES-256-GCM under the derived license key.
- Revocation handling: throws `DaywalkerAuthError` on `SERVICE_REVOKED`, `SERVICE_SUSPENDED`, `DOMAIN_REVOKED`, or `DOMAIN_MISMATCH`.
- Backward compatible with `validateServiceCredentials()` and requires no new environment variables.
- Exported types: `License`, `LicenseOptions`, `ConfigBundle`.

## 0.8.0
**Service licensing** (needs the auth.daywalker.dev release with per-service licenses and `POST /api/v1/services/:slug/bundle`). Fully additive; `validateServiceCredentials()` is unchanged.
- New `client.getLicense({ serviceSlug?, forceRefresh? })` returning `{ serviceSlug, licenseKey, expiresAt }`. The key is derived by Daywalker per service, signing key and one-hour window, comes with the client credentials grant, and is cached in memory until a minute before it expires. It is never part of `TokenSet` or `toJSON()`.
- New `client.fetchBundle({ serviceSlug?, forceRefresh? })` returning the config bundle (`serviceSlug`, `dataKeySalt`, `features`, `issuedAt`, `expiresAt`). It is sealed with AES-256-GCM under the license key and opened locally; at a window rollover the license is refreshed once and the bundle opened again. Frozen result, cached until a minute before it expires.
- Errors are `DaywalkerAuthError`s with Daywalker's code: `SERVICE_REVOKED`, `SERVICE_SUSPENDED`, `DOMAIN_REVOKED`, `DOMAIN_MISMATCH`; the SDK adds `LICENSE_UNAVAILABLE` (403, granted without a license) and `BUNDLE_UNREADABLE` (502).
- New exported types `License`, `LicenseOptions`, `ConfigBundle`.

## 0.7.0
**OAuth access tokens instead of the API key, and hardening against tampering.** Follows the Daywalker API docs: `POST /api/v1/tokens/validate` requires `Authorization: DPoP <access_token>`, and bearer API keys are refused with `401 DPOP_REQUIRED`.

**OAuth**
- **Breaking:** `client.fetch()` and `validateToken()` no longer send `Authorization: Bearer <apiKey>`. They send `Authorization: DPoP <access token>` with a DPoP proof, getting and refreshing the token through the client credentials flow (`accessToken()`) on demand. A `401 ACCESS_TOKEN_EXPIRED` refreshes the token and retries once.
- `DAYWALKER_API_KEY` is now only the OAuth client credential: it is sent on the `client_credentials` grant (with the RFC 9421 signature) and by `daywalker init` / `rotate` to register the signing key, nowhere else. The `refresh_token` grant no longer sends it.
- `getTokens()` narrows the grant to the configured service slug(s) by default (least privilege).
- A failed client credentials grant makes `validateToken()` return `503 SERVICE_UNAVAILABLE` (never a `401` for the caller's token); a missing `DAYWALKER_API_KEY` is `500 CONFIGURATION_ERROR`.
- New `client.validateServiceCredentials()`: the service health check runs the client credentials grant and checks the granted services (`403 SERVICE_NOT_GRANTED` when the configured service isn't covered). `createDaywalkerServiceHealthMiddleware` and `npx daywalker check` use it (`check --offline` skips it).

**Removed (API-key-era leftovers)**
- **Breaking:** `validateServiceKey()`, `signRequest({ apiKey })`, the Express `daywalkerKeys()` key-pull endpoint (`/.well-known/daywalker-keys.json`; keys are registered by push with `POST /api/v1/keys/register`), the unused `src/signing.ts`, and the CLI's `--api-key <key>` flag (now an error; use `DAYWALKER_API_KEY` or `--api-key-stdin`).
- **Breaking:** offline verification accepts only RFC 9068 access tokens: `typ: at+jwt`, `alg: EdDSA`, and the service in `aud`. Lease-era tokens (`typ: JWT`, a `serviceSlug` claim, `alg: ed25519`) are refused, and `leaseServices()` no longer reads `serviceSlug` / `service`.

**Offline verification survives key rotation**
- New `jwks: "auto"` / `DAYWALKER_JWKS=auto`: offline verification uses Daywalker's JWKS, fetched only from `${authUrl}/.well-known/jwks.json` (never a `jwks_uri` from elsewhere) and kept in the client for 10 minutes (`JWKS_CACHE_TTL_MS`). An unknown `kid` refetches the set, at most once per 30 seconds (`JWKS_REFETCH_COOLDOWN_MS`); a failed refresh keeps the last good set. Only Ed25519 / EdDSA signing keys with a `kid` are used. With no set available, the static `daywalkerPublicKey` is used if configured; otherwise `offlineOnly` validation returns `503 SERVICE_UNAVAILABLE` and normal validation goes online. The static key path is unchanged when `jwks` is off (the default).

**Signing key provisioning**
- New `keyStore` option: on first use the client loads its signing key from the store, or generates one, registers it for the detected domain (`POST /api/v1/keys/register`) and saves it with an atomic `saveIfAbsent`, so `DAYWALKER_SIGNING_KEY` no longer has to be copied into every environment. Built-in `fileKeyStore()` (`@shelbyb/daywalker-sdk/keystore/file`), `memoryKeyStore()` and read-only `envKeyStore()` (`@shelbyb/daywalker-sdk/keystore`); any store with create-if-absent semantics works. Only registered keys are stored; loads check the keyId thumbprint and domain; provisioned keys are non-extractable. New `client.provisionSigningKey()` and `importSigningKey()`.
- New `signer` option for KMS / HSM keys: requests are signed through the callback, so the private key never exists in the app. It's checked once against `publicJwk` when given, and captured at construction. `signRequest()` accepts `signer` in place of `key`.
- `selfCheck()` reports what first-use provisioning needs without provisioning anything.

**Signing key lifecycle** (Daywalker's key slots, expiry, list and revoke APIs)
- **Fix:** every key the SDK and CLI register now gets its own `instanceId` slot (`dw-<keyId>`). Daywalker retires every other slot-less key of a domain 10 minutes after a registration without `instanceId`. Without the slot, `daywalker rotate` would have broken the deployed key 10 minutes later, and racing auto-provisioning instances would have retired each other's keys.
- New ephemeral mode (`ephemeralKey`, env `DAYWALKER_EPHEMERAL_KEY` / `DAYWALKER_KEY_TTL_SECONDS` / `DAYWALKER_INSTANCE_ID`): a non-extractable in-memory key registered with a lifetime in this process's slot and replaced in place before it expires (in the background while the old key is still good, retried at most every 30s). Tokens from before a replacement are treated as stale, so the next OAuth session uses the new key. `client.close()` revokes the key; the client then refuses further use. Can't be combined with `keyStore`.
- New `listSigningKeys()`, `revokeSigningKey()`, `keySlotFor()`; `registerPublicKey()` takes `instanceId`, `ttlSeconds`, `expiresAt`, returns Daywalker's error `code` and the key record, and refuses an answer about another key. The key API calls refuse redirects, time out, skip caches and bound answers.
- Auto-provisioning revokes the key it registered when another instance stored one first, instead of only warning.
- `KEY_LIMIT_REACHED` errors explain how to free a slot. New CLI commands `daywalker keys` and `daywalker revoke <keyId>` (refuses the current `DAYWALKER_KEY_ID` without `--force`); `init --force` and `rotate` print the revoke command for the previous key.

**Hardening**
- **Breaking:** incoming DPoP-bound access tokens (`cnf.jkt`) need `Authorization: DPoP` and a valid DPoP proof (method, URL, key thumbprint, `ath`, fresh `iat`, single-use `jti`), checked even for cached results. New `verifyDpopProof()`, `publicOrigin` / `DAYWALKER_PUBLIC_ORIGIN` (for proxies) and `dpopReplayStore`.
- **Breaking:** an online validation answer must name the service it was validated for, and that must be this service. A token for a sibling service the credentials also cover is refused with `403 SERVICE_NOT_GRANTED`; an answer naming no service fails closed (503). Adapters map 403 through.
- **Breaking:** client state is in ES `#private` fields; the class, its prototype and instances are frozen; the default `daywalker` proxy refuses writes. `client.config` is frozen and shows secrets as `"[configured]"`. The options object is read once.
- WebCrypto is captured at load, so patching `crypto.subtle` later can't fool verification. The SDK's DPoP key is non-extractable.
- The Next adapter no longer uses a `NextResponse` from `globalThis`.
- Adapters share one strict credential reader (`readCredentials`): `Bearer` or `DPoP` only, no silent fallback to `x-api-token` behind an unknown `Authorization` scheme, no repeated headers, length caps.
- Incoming tokens must be ≤ 8 KiB of token characters, or they're refused without calling Daywalker. `cacheTtlMs` and `negativeCacheTtlMs` are capped at 5 minutes.
- Token endpoint answers are checked: `token_type` must be `DPoP`, tokens must be well-formed, the lifetime is capped at what `expires_in` allows, and results are frozen. Response bodies from Daywalker are capped at 1 MiB, and requests use `cache: "no-store"`.
- `registerPublicKey()` refuses redirects, times out after 10s, and validates the domain, service slugs, API key and public JWK before sending anything. `authUrl` / `publicOrigin` can't carry credentials. `hexToBytes()` rejects invalid hex.

## 0.6.0
**Client credentials flow with rotating refresh tokens. Needs Daywalker Auth with `POST /api/v1/oauth/token`; breaking for `issueLease()` users.**
- New `client.getTokens({ scope?, expiresIn? })`, `client.refreshTokens()` and `client.accessToken()` (auto-refresh, serialized, falls back to the client credentials when the session ended). **`issueLease()` is removed** (`/api/v1/leases/issue` no longer exists).
- No request carries a service slug any more: `validateToken()` stops sending `serviceSlug`, `DAYWALKER_SERVICE_SLUG` is optional (offline audience check only), and `init` / `rotate` no longer require `--service` or send a slug when registering a key.
- `verifyJwtLease()` is stricter: requires `jti`, accepts `typ` `JWT` or `at+jwt` (never `rt+jwt`), caps clock skew at 30 s (was 60 s), and the client checks `iss` against `https://auth.daywalker.dev` unless `leaseIssuer` is set.
- New `buildTokenCookie`, `clearTokenCookie`, `daywalkerCookies` (HttpOnly, Secure, SameSite=Strict/Lax cookies) and `accessTokenUser(payload)` for the verified `user` claim (UUID v7 `id`, `name`, `email`).

## 0.5.0
**One API key, several services.** Needs Daywalker Auth with multi-service tokens; the SDK also works unchanged against older servers.
- `client.issueLease()` returns `services`, every service slug the JWT lease covers (its `services` and `aud` claims). It takes `{ ttlSeconds?, services? }` (a bare number still works); `services` narrows the lease, and a service the key doesn't cover is refused with `403 SERVICE_NOT_GRANTED`.
- `validateToken()` reports `data.services`: the services an offline-verified lease covers, or the ones an online-validated token covers (just the validated slug against older servers).
- `verifyJwtLease()` also requires the expected service to be in the lease's `services` claim when it has one. New `leaseServices(payload)` helper.
- `DAYWALKER_SERVICE_SLUG` / `serviceSlug` accept a comma-separated list (`gigpulse,devpulse`); the first is the default. `serviceSlugs` option, `config.serviceSlugs`, `selfCheck().serviceSlugs`, `parseServiceSlugs()`.
- `daywalker init` / `rotate` take `--service gigpulse,devpulse` and send `serviceSlug` when registering the key, so a key for a service the API key doesn't cover fails immediately with `service_not_covered`.
- package.json: the description no longer says "zero-dependency" (`re2js` has been a runtime dependency since 0.4.0).
- Internal maintenance notes in `docs/maintenance/` are excluded from the published package.

## 0.4.1
No code changes.
- Published from GitHub Actions with npm trusted publishing (OIDC) and a provenance attestation, instead of from a maintainer's machine.
- Publish workflow: runs never overlap, and a version already on npm fails early with a clear error.
- README: badges, the `./express` entry point, and how releases and provenance work.

## 0.4.0
Security and reliability fixes from an audit of the whole package. Several are **breaking**; read those before upgrading from 0.3.

**Package**
- **Breaking:** Node.js 20.19+ (was documented as 18+). `require()` of the package works on Node 20.19+ / 22.12+ via the new `default` export conditions.
- **Breaking:** one runtime dependency, [`re2js`](https://www.npmjs.com/package/re2js): flag `matches` rules run on RE2 (linear time), so no pattern can hang evaluation. The 0.3 nested-quantifier heuristic is gone; patterns RE2 can't compile (backreferences, lookarounds) never match.
- The publish workflow builds in a job without `id-token: write`; only the job that runs `npm publish` gets the OIDC token. CI checks the packed tarball with publint and attw.

**Core client and signing**
- **Breaking:** validation fails closed. A network error, timeout or 5xx from Daywalker returns `SERVICE_UNAVAILABLE` (503) instead of anything that could be read as valid, and malformed validation responses are rejected.
- **Breaking:** requests time out after 5s per attempt (`timeoutMs`; 0 disables). Network errors and timeouts are retried only for GET/HEAD/OPTIONS or with an `idempotencyKey`. `Retry-After` is honored up to 60s (`retry.maxRetryAfterMs`); a longer one returns the 429.
- **Breaking:** redirects are never followed with credentials; a 3xx from Daywalker is an error.
- **Breaking (signatures):** the query string is covered as `"@query"`, so it can't be changed in transit. `"content-digest"` is covered for POST/PUT/PATCH and any request with a body, and verification requires it then. Verification builds the base from the components listed in `Signature-Input`. Bodyless GET/HEAD/DELETE/OPTIONS requests no longer get a digest of an empty body. Test vectors include a `query-get` case.
- **Breaking (leases):** JWTs with a `crit` header, non-canonical base64url or a `kid` missing from a JWKS are rejected. `daywalkerPublicKey` accepts a JWKS and selects the key by `kid`.
- The replay cache fails closed when full instead of evicting live entries, and takes a pluggable `replayStore` for multi-instance deployments.
- `client.keys()` also publishes `DAYWALKER_SIGNING_KEY_PREVIOUS` during rotation. Cached results are cloned, so callers can't mutate the cache.

**Middleware (`./next`, `./middleware`, `./express`)**
- **Breaking:** paths are decoded and normalized before the bypass check (`/_next/static/../admin`, `%2e%2e`, `//`, encoded slashes). Static file extensions no longer skip auth; exclude public files with Next's `matcher`, or set `staticFileExtensions` (e.g. `STATIC_FILE_EXTENSIONS`).
- **Breaking:** error redirects carry no `message` parameter (only a fixed `error` code and `status`). The `from` return path is dropped when it could point off-site (tabs, backslashes, `//host`). With `allowedHosts`, a request without a `Host` header is refused too.
- Daywalker outages answer `503` and configuration errors `500`, instead of `401`.
- `createDaywalkerProxy` / `createDaywalkerServiceHealthProxy` aliases for Next.js 16 `proxy.ts`.

**CLI**
- **Breaking:** `init` and `rotate` write `.env.local` only after registration succeeds and exit non-zero otherwise; `--skip-register` writes without registering. Writes are atomic with mode `0600`.
- `--api-key-stdin` reads the key from stdin. `init --force` keeps the replaced key as `DAYWALKER_SIGNING_KEY_PREVIOUS`. `--json` warns on stderr that its output contains the private key.

**Flags, OpenFeature, analytics**
- **Breaking:** `allFlagsState()` defaults to `clientSideOnly: true`, so server-only flags don't end up in a browser bootstrap by accident.
- Browser SSE no longer sends headers that force a CORS preflight; each connection gets a fresh parser; `restart()` no longer leaks a timer; a server `retry:` below 1s is raised to 1s; events over 1MB are refused.
- `identify()` ignores responses that arrive out of order. New `offline` option. New `stale` / `recovered` events when the stream drops and comes back.
- React: the client is created in an effect (StrictMode-safe), never opens a connection during server rendering, and records evaluations after commit.
- Events and analytics batches are split under the 64KB `keepalive` and body limits. Opting out of analytics drops queued events. New `sanitizePath` option.
- OpenFeature: `Date` context values are serialized as ISO strings; providers emit ERROR / STALE / READY; a client you pass in is not closed by the provider.
- Shared evaluation test vectors: [`test-vectors/flags-eval.json`](./test-vectors/flags-eval.json).

## 0.3.0
Security fixes. Released as a minor version (not 0.2.1) because several changes are breaking: `^0.2.x` ranges won't pick it up automatically. Items marked **breaking** change behavior existing code may rely on.

- **Breaking:** `validateToken()` / `requireValidToken()` without a token now fail with `INVALID_TOKEN` (401) instead of validating the service's own `DAYWALKER_API_KEY`. Use the new `validateServiceKey()` for a service health check.
- **Breaking:** `createDaywalkerMiddleware` (`./next`) authenticates each request's `Authorization: Bearer` / `x-api-token`; requests without one get 401 (API routes) or the `errorPath` redirect (pages, unless `protectApiOnly`). The old service-key gate is now `createDaywalkerServiceHealthMiddleware`.
- **Breaking:** the Next middleware only skips `/_next/static/`, `/_next/image`, `/favicon.ico` and files with a static extension (`.js .css .png .jpg .jpeg .gif .webp .avif .svg .ico .woff .woff2 .map .txt`) outside `/api/`. `/_next/data/` and dotted API paths are now authenticated.
- **Breaking:** offline JWT leases must carry a numeric `exp` and an `aud` or `serviceSlug` equal to the expected service slug; a verifier with no service slug configured rejects every lease (`validateToken` then falls back to online validation unless `offlineOnly`). `typ`, when present, must be `JWT`. New `leaseIssuer` / `DAYWALKER_LEASE_ISSUER` checks `iss`. `exp`/`nbf` allow 60s clock skew.
- **Breaking:** `authUrl`, flags `baseUrl` and analytics `host` must be `https://` (plain `http://` only for `localhost`, `127.0.0.1`, `[::1]`); constructors throw otherwise. `Daywalker#fetch()` throws for URLs outside the `authUrl` origin, so the API key is never sent elsewhere.
- **Breaking:** analytics `$current_url`, `$referrer` and their `$initial_*` versions drop the fragment and every query parameter except `utm_*`, `gclid`, `fbclid` and `ref`. Set `captureFullUrls: true` to keep full URLs.
- **Breaking:** flag `matches` clauses never match inputs over 1024 characters, patterns over 500 characters, or patterns with nested quantifiers such as `(a+)+` or `(a|aa)+` (logged once).
- RFC 9421 replay protection keys on the decoded signature bytes plus `keyid`, accepts only the padded standard-base64 `:…:` form, records a signature only after it verifies, keeps entries for 2 × `maxClockSkewSeconds`, and caps the cache at 10,000 entries.
- The token validation cache is capped at 1,000 entries (least recently used evicted), keyed by a SHA-256 of the token, and never keeps an offline lease past its `exp`.
- Context attributes and browser flag lookups ignore inherited properties (`__proto__`, `constructor`, `toString`).
- Private attributes given as nested JSON pointers (e.g. `/address/zip`) are now redacted from events.
- CLI: `.env.local` is chmodded to `0600` even when it already existed, and `--api-key` prints a warning (prefer `DAYWALKER_API_KEY`).
- Publish workflow: dependencies install with `--ignore-scripts`, npm is pinned, and tag releases must point at a commit on `main`.

## 0.2.0
- **One package for DevPulse:** the DevPulse client SDKs move here as subpath exports — `./flags` (browser), `./flags/node`, `./flags/react`, `./flags/engine`, `./openfeature/server`, `./openfeature/web` and `./analytics`. They replace `@devpulse/js-client`, `@devpulse/node`, `@devpulse/react`, `@devpulse/openfeature` and `@devpulse/analytics`; imports change, APIs don't.
- `react` and the OpenFeature SDKs are optional peer dependencies; the package stays dependency-free.
- Fix: closing a flags client no longer leaves the 5-minute stream read-timeout timer (or a pending read) keeping a Node process alive, and `waitForInitialization()` clears its timeout once ready.

## 0.1.4
- Fix: every signed request now carries a unique `nonce` in `Signature-Input` (fresh per attempt, including 429 retries), so identical requests in the same second no longer yield byte-identical Ed25519 signatures and trigger `Replay detected`.
- `validateToken()` deduplicates concurrent in-flight validations per `serviceSlug:token`.
- New `negativeCacheTtlMs` config (default 3000ms, 0 disables) briefly caches failed validations; 429 and network errors are never cached.
- Server (`daywalker-api-service`) already keys replays on the signature hash and signs the raw `Signature-Input` params, so the nonce makes signatures unique; older SDKs without a nonce remain accepted.
