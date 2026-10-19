// Push good/total events to a custom SLO. Env: DEVPULSE_URL, DEVPULSE_CLIENT_ID, DEVPULSE_CLIENT_SECRET (scope slo:ingest).
import { createApiClient } from "@shelbyb/daywalker-sdk/api";
import { createSloReporter } from "@shelbyb/daywalker-sdk/slo";

const api = createApiClient({ host: process.env.DEVPULSE_URL!, clientId: process.env.DEVPULSE_CLIENT_ID!, clientSecret: process.env.DEVPULSE_CLIENT_SECRET!, scope: "slo:ingest" });
const slo = createSloReporter({ api, project: "web", slo: "checkout-success", onError: (err, events) => console.warn("SLO batch not sent", events.length, err) });

slo.observe(true); // one good request
slo.record(98, 100); // or counts
await slo.shutdown();
