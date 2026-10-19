// Monitor a scheduled job. Env: DEVPULSE_PING_URL (https://<host>/ping/<token>; keep it secret).
import { createCronMonitor } from "@shelbyb/daywalker-sdk/cron";

const cron = createCronMonitor({ pingUrl: process.env.DEVPULSE_PING_URL!, onError: (e) => console.warn("ping failed", e) });

// start ping, then success, or fail with the error text (the error is rethrown)
await cron.wrap(async () => {
  await cron.log("exporting invoices");
  // ... the job ...
});

// Or report a shell-style exit code:
await cron.exitCode(0, "exported 42 invoices");
