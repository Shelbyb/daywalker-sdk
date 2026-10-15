# @shelbyb/daywalker-sdk/flags

Feature flags for browsers (and any JavaScript client) from [DevPulse](https://github.com/shelbyb/devpulse). Flag changes arrive in real time over Server-Sent Events, typically within tens of milliseconds of a change in the dashboard.

```bash
npm install @shelbyb/daywalker-sdk
```

```ts
import { createClient } from "@shelbyb/daywalker-sdk/flags";

const client = createClient(
  "YOUR_CLIENT_SIDE_ID", // Project → Environments & keys
  { kind: "user", key: user.id, email: user.email },
  { baseUrl: "https://devpulse.example.com" },
);

await client.waitForInitialization({ timeoutMs: 3000 });

if (client.variation("new-checkout", false)) showNewCheckout();

// React to changes made in the dashboard, live
client.on("change:new-checkout", (enabled) => (enabled ? showNewCheckout() : showOldCheckout()));

// Metrics and experiments
client.track("checkout-completed", { items: 3 }, 129.5);

// After login
await client.identify({ kind: "user", key: newUser.id });
```

Only flags marked **Available to client-side SDKs** are visible.

## Options

| Option | Default | |
| --- | --- | --- |
| `baseUrl` | — | Your DevPulse URL |
| `streaming` | `true` | Real-time updates (SSE). `false` fetches once |
| `bootstrap` | — | Initial values, e.g. from `@shelbyb/daywalker-sdk/flags/node`'s `allFlagsState().toJSON()` |
| `hash` | — | Secure mode hash (`HMAC-SHA256(sdkKey, contextKey)`), computed on your server |
| `withReasons` | `false` | Include evaluation reasons for `variationDetail()` |
| `sendEvents` | `true` | Analytics for insights and experiments |
| `privateAttributes` / `allAttributesPrivate` | — | Attributes never sent to DevPulse |
| `cache` | `false` | Persist the last flags in `localStorage` and use them while loading |
| `offline` | `false` | Serve only `bootstrap`/cached values and open no connection (tests, server rendering) |

## Contexts

Single kind: `{ kind: "user", key: "u1", plan: "pro" }`. Multi-kind: `{ kind: "multi", user: { key: "u1" }, organization: { key: "acme" } }`.

## API

`variation(key, default)`, `variationDetail(key, default)`, `boolVariation` / `stringVariation` / `numberVariation` / `jsonVariation`, `allFlags()`, `identify(context)`, `track(key, data?, metricValue?)`, `on("ready" | "failed" | "change" | "change:<key>" | "stale" | "recovered", fn)` (`stale`: the stream dropped and the last flags keep serving; `recovered`: it reconnected), `flush()`, `close()`.
