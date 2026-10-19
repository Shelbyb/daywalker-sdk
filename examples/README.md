# Examples

One small, type-checked file per use case. `npm run check:examples` builds the package and compiles every file here against the package's own published types (`tsc -p examples/tsconfig.json`); CI runs it. Nothing here runs in CI or reaches the network. Configuration comes from environment variables; never commit real keys.

| Import | Example |
|---|---|
| `@shelbyb/daywalker-sdk` | [auth-validate-token.ts](./auth-validate-token.ts), [auth-signed-fetch.ts](./auth-signed-fetch.ts) |
| `@shelbyb/daywalker-sdk/next` | [next-proxy.ts](./next-proxy.ts), [next-route-handler.ts](./next-route-handler.ts) |
| `@shelbyb/daywalker-sdk/middleware` | [middleware-web.ts](./middleware-web.ts) |
| `@shelbyb/daywalker-sdk/express` | [express-node-http.ts](./express-node-http.ts) |
| `@shelbyb/daywalker-sdk/keystore`, `/keystore/file` | [keystore-memory-env.ts](./keystore-memory-env.ts), [keystore-file.ts](./keystore-file.ts) |
| `@shelbyb/daywalker-sdk/flags` | [flags-browser.ts](./flags-browser.ts) |
| `@shelbyb/daywalker-sdk/flags/node` | [flags-node.ts](./flags-node.ts) |
| `@shelbyb/daywalker-sdk/flags/react` | [flags-react.tsx](./flags-react.tsx) |
| `@shelbyb/daywalker-sdk/flags/engine` | [flags-engine.ts](./flags-engine.ts) |
| `@shelbyb/daywalker-sdk/openfeature/server` | [openfeature-server.ts](./openfeature-server.ts) |
| `@shelbyb/daywalker-sdk/openfeature/web` | [openfeature-web.ts](./openfeature-web.ts) |
| `@shelbyb/daywalker-sdk/analytics` | [analytics-browser.ts](./analytics-browser.ts), [analytics-server.ts](./analytics-server.ts), [analytics-web-vitals.ts](./analytics-web-vitals.ts) |
| `@shelbyb/daywalker-sdk/api` | [api-client.ts](./api-client.ts) |
| `@shelbyb/daywalker-sdk/webhooks` | [webhooks-verify.ts](./webhooks-verify.ts) |
| `@shelbyb/daywalker-sdk/cron` | [cron-wrap.ts](./cron-wrap.ts) |
| `@shelbyb/daywalker-sdk/logs` | [logs.ts](./logs.ts) |
| `@shelbyb/daywalker-sdk/secrets`, `/secrets/env` | [secrets.ts](./secrets.ts), [secrets-env.ts](./secrets-env.ts) |
| `@shelbyb/daywalker-sdk/oncall` | [oncall.ts](./oncall.ts) |
| `@shelbyb/daywalker-sdk/slo` | [slo.ts](./slo.ts) |
| `@shelbyb/daywalker-sdk/deploys` | [deploys.ts](./deploys.ts) |

A test (`test/examples.test.ts`) fails when a subpath export has no example here.

## Other languages (reference examples)

The SDK itself is Node.js/TypeScript. For Python, Go and Ruby these examples validate a token with an RFC 9421 signed request (same signature base as `test-vectors/signing-rfc9421.json`):

- `python/validate_token.py` (needs `cryptography`)
- `go/validate_token/main.go` (stdlib)
- `ruby/validate_token.rb` (stdlib)

Env: `DAYWALKER_API_KEY`, `DAYWALKER_KEY_ID`, `DAYWALKER_SIGNING_KEY` (base64 PKCS#8 Ed25519), optional `DAYWALKER_URL`.
