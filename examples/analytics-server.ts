// Server-side analytics: pass who did it, flush before exit. Env: DEVPULSE_WRITE_KEY, DEVPULSE_URL.
import { createAnalytics } from "@shelbyb/daywalker-sdk/analytics";

const analytics = createAnalytics({ writeKey: process.env.DEVPULSE_WRITE_KEY!, host: process.env.DEVPULSE_URL! });
analytics.capture("invoice_paid", { amount: 49 }, { distinctId: "customer-42" });
await analytics.shutdown();
