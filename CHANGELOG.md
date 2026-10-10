# Changelog

## 0.1.4
- Fix: every signed request now carries a unique `nonce` in `Signature-Input` (fresh per attempt, including 429 retries), so identical requests in the same second no longer yield byte-identical Ed25519 signatures and trigger `Replay detected`.
- `validateToken()` deduplicates concurrent in-flight validations per `serviceSlug:token`.
- New `negativeCacheTtlMs` config (default 3000ms, 0 disables) briefly caches failed validations; 429 and network errors are never cached.
- Server (`daywalker-api-service`) already keys replays on the signature hash and signs the raw `Signature-Input` params, so the nonce makes signatures unique; older SDKs without a nonce remain accepted.
