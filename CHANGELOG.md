# Changelog

## 0.2.1
Security fixes. Items marked **breaking** change behavior existing code may rely on.

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
