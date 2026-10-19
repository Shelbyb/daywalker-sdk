# Runtime support

| Subpath | Node 20.19+ | Browsers | Deno | Bun | Cloudflare Workers / edge |
| --- | --- | --- | --- | --- | --- |
| `/flags`, `/flags/engine`, `/flags/react`, `/openfeature/web` | yes | yes | yes | yes | yes |
| `/flags/node`, `/openfeature/server` | yes | n/a (server key) | yes | yes | yes |
| `/analytics` (incl. `captureWebVitals`) | yes | yes | yes | yes | yes |
| `/api` | yes | not for secrets | yes | yes | yes |
| `/` (Daywalker auth), `/next`, `/middleware`, `/express`, `/keystore`, `/cli` | yes | no | no | no | no |

The flags, analytics, API, webhooks, cron, logs, secrets (and `secrets/env`), oncall, slo and deploys entry points import no Node built-ins (no `node:crypto`, `node:events`, `Buffer` or `process`): they use `fetch`, `TextEncoder`, `URL`, `AbortSignal` and Web Crypto-free pure code (SHA-1, SHA-256/HMAC and RE2 are implemented in JavaScript). The only runtime dependency is `re2js`. A test (`test/runtime-compat.test.ts`) walks each portable entry's import graph and fails on any Node built-in.

The package is ESM only (`"type": "module"`, `exports` with `types`, `import` and `default`) with `"sideEffects": false`, so bundlers drop unused code. On Node 20.19+ `require()` of ESM works as well. Workers: `/flags/node` streams over SSE with `fetch`; use `stream: false` (polling) if your platform limits long-lived requests, and `await client.flush()` before the response ends (or `ctx.waitUntil`).

Type-checked examples for every entry point: [`examples/`](../examples/README.md).
