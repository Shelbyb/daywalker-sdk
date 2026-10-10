# Changelog

## 0.2.0
- **One package for DevPulse:** the DevPulse client SDKs move here as subpath exports — `./flags` (browser), `./flags/node`, `./flags/react`, `./flags/engine`, `./openfeature/server`, `./openfeature/web` and `./analytics`. They replace `@devpulse/js-client`, `@devpulse/node`, `@devpulse/react`, `@devpulse/openfeature` and `@devpulse/analytics`; imports change, APIs don't.
- `react` and the OpenFeature SDKs are optional peer dependencies; the package stays dependency-free.
- Fix: closing a flags client no longer leaves the 5-minute stream read-timeout timer (or a pending read) keeping a Node process alive, and `waitForInitialization()` clears its timeout once ready.

## 0.1.4
- Fix: every signed request now carries a unique `nonce` in `Signature-Input` (fresh per attempt, including 429 retries), so identical requests in the same second no longer yield byte-identical Ed25519 signatures and trigger `Replay detected`.
- `validateToken()` deduplicates concurrent in-flight validations per `serviceSlug:token`.
- New `negativeCacheTtlMs` config (default 3000ms, 0 disables) briefly caches failed validations; 429 and network errors are never cached.
- Server (`daywalker-api-service`) already keys replays on the signature hash and signs the raw `Signature-Input` params, so the nonce makes signatures unique; older SDKs without a nonce remain accepted.
