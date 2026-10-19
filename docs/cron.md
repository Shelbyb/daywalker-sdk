# Cron monitoring: `@shelbyb/daywalker-sdk/cron`

Heartbeat pings for DevPulse cron checks. The ping URL (`https://<host>/ping/<token>`) contains the check's token by design of the protocol: keep it in an environment variable and never log it (`toJSON()` redacts it).

```ts
import { createCronMonitor } from "@shelbyb/daywalker-sdk/cron";

const cron = createCronMonitor({ pingUrl: process.env.DEVPULSE_PING_URL! });
await cron.wrap(async () => runNightlyExport()); // start, then success or fail (with the error text)
```

| Method | Request | Meaning |
|---|---|---|
| `start(body?)` | `/ping/{token}/start` | Job started (duration and stuck-run detection) |
| `success(body?)` | `/ping/{token}` | Job succeeded |
| `fail(body?)` | `/ping/{token}/fail` | Job failed |
| `log(body)` | `/ping/{token}/log` | Message, no state change |
| `exitCode(code, body?)` | `/ping/{token}/{0-255}` | 0 is success, anything else failure |
| `wrap(fn)` | start, then success or fail | Rethrows the job's error |

Calls without a body use GET; with a body, POST `text/plain` truncated to the 10,000 characters DevPulse keeps. Pings never throw: they resolve `{ ok, status }` and report failures to `onError`, so a monitoring outage never fails the job. Options: `timeoutMs` (10 s), `fetch`.
