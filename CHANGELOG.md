# Changelog

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
