# @shelbyb/daywalker-sdk/openfeature

[OpenFeature](https://openfeature.dev) providers for DevPulse. Use the vendor-neutral OpenFeature API and swap providers without touching application code.

```bash
npm install @shelbyb/daywalker-sdk @openfeature/server-sdk   # servers
npm install @shelbyb/daywalker-sdk @openfeature/web-sdk      # browsers
```

```ts
// Server
import { OpenFeature } from "@openfeature/server-sdk";
import { DevPulseServerProvider } from "@shelbyb/daywalker-sdk/openfeature/server";

await OpenFeature.setProviderAndWait(new DevPulseServerProvider(process.env.DEVPULSE_SDK_KEY!, { baseUrl }));
const client = OpenFeature.getClient();
const enabled = await client.getBooleanValue("new-checkout", false, { targetingKey: user.id, plan: "pro" });
```

```ts
// Browser
import { OpenFeature } from "@openfeature/web-sdk";
import { DevPulseWebProvider } from "@shelbyb/daywalker-sdk/openfeature/web";

await OpenFeature.setContext({ targetingKey: user.id });
await OpenFeature.setProviderAndWait(new DevPulseWebProvider(clientSideId, { baseUrl }));
OpenFeature.getClient().getBooleanValue("new-checkout", false);
```

`targetingKey` maps to the context key, and a `kind` attribute selects the context kind (default `user`). Flag changes emit `PROVIDER_CONFIGURATION_CHANGED`. Reasons map to OpenFeature's standard reasons: `TARGETING_MATCH`, `SPLIT`, `DEFAULT`, `DISABLED`, `ERROR`.

Examples: [`examples/`](../examples/README.md).
