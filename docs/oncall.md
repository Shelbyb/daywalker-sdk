# On-call: `@shelbyb/daywalker-sdk/oncall`

Trigger, acknowledge and resolve pages through DevPulse's PagerDuty-compatible Events API v2 (`POST {host}/oncall/v2/enqueue`). The routing key (an escalation policy's integration key) travels in the JSON body.

```ts
import { createOncall } from "@shelbyb/daywalker-sdk/oncall";

const oncall = createOncall({ host: process.env.DEVPULSE_URL!, routingKey: process.env.DEVPULSE_ROUTING_KEY! });
const { dedupKey } = await oncall.trigger({ summary: "DB disk 95% full", severity: "critical", source: "db-1", dedupKey: "db-1-disk" });
await oncall.resolve(dedupKey);
```

Use a stable `dedupKey` per problem: repeated triggers update one page, and acknowledge/resolve need it. `trigger` accepts `summary` (required, max 1024), `severity` (`critical` | `error` (default) | `warning` | `info`), `source`, `component`, `group`, `class`, `customDetails` (< 64 KB) and up to 10 `links`. Events over 512 KB are refused locally. Non-2xx answers throw `DevPulseHttpError` (400 invalid event or unknown routing key, 429 with `retryAfter`).
