# @shelbyb/daywalker-sdk/flags/node

Server-side feature flags for Node.js from [DevPulse](https://github.com/shelbyb/devpulse). The SDK downloads your flag rules once, keeps them current over a streaming connection, and evaluates locally, so `variation()` adds no network latency.

```bash
npm install @shelbyb/daywalker-sdk
```

```ts
import { init } from "@shelbyb/daywalker-sdk/flags/node";

export const flags = init(process.env.DEVPULSE_SDK_KEY!, { baseUrl: "https://devpulse.example.com" });
await flags.waitForInitialization({ timeoutMs: 5000 });

const context = { kind: "user", key: user.id, email: user.email, plan: user.plan };
if (await flags.variation("new-checkout", context, false)) {
  // …
}

flags.on("update:new-checkout", () => console.log("new-checkout changed"));
flags.track("checkout-completed", context, undefined, order.total);
```

Create one client per process and reuse it. Call `await flags.close()` on shutdown to flush analytics.

## Next.js (App Router): bootstrap the browser without a flicker

```tsx
// app/layout.tsx (Server Component)
import { flags } from "@/lib/flags";
import { Providers } from "./providers";

export default async function Layout({ children }) {
  const context = await currentUserContext();
  const bootstrap = (await flags.allFlagsState(context, { clientSideOnly: true })).toJSON();
  const hash = flags.secureModeHash(context); // if secure mode is on
  return <Providers context={context} bootstrap={bootstrap} hash={hash}>{children}</Providers>;
}
```

See `@shelbyb/daywalker-sdk/flags/react` for the `Providers` component.

## Options

`baseUrl`, `stream` (default `true`; falls back to polling if streaming keeps failing), `pollIntervalMs` (≥ 30s), `sendEvents`, `privateAttributes`, `allAttributesPrivate`, `offline`, `initialData` (fixtures for tests), `logger`.

## API

`variation` / `variationDetail` (async) and `variationSync` / `variationDetailSync`, typed helpers (`boolVariation`, …), `allFlagsState(context, { clientSideOnly, withReasons })`, `secureModeHash(context)`, `track`, `identify`, `on("ready" | "failed" | "update" | "update:<key>")`, `flush()`, `close()`.
