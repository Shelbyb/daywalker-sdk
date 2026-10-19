# SLO events and deploy markers: `/slo` and `/deploys`

Both use the management API client (`@shelbyb/daywalker-sdk/api`) and its OAuth client credentials.

## `@shelbyb/daywalker-sdk/slo`

Push good/total counts to a custom (push) SLO: `POST /api/v1/projects/{project}/slos/{slo}/events` (scope `slo:ingest`).

```ts
import { createApiClient } from "@shelbyb/daywalker-sdk/api";
import { createSloReporter } from "@shelbyb/daywalker-sdk/slo";

const api = createApiClient({ host, clientId, clientSecret, scope: "slo:ingest" });
const slo = createSloReporter({ api, project: "web", slo: "checkout-success" });
slo.observe(res.ok);        // or slo.record(good, total)
await slo.shutdown();
```

**Not idempotent.** DevPulse adds counts to their time bucket, so a resent batch counts twice. The reporter therefore aggregates counts per minute, sends each batch (up to 1,000 events) exactly once, and never retries a batch whose outcome is unknown: it hands it to `onError(err, events)` instead. Only 429 is retried (by the API client, before the request is accepted). Timestamps must fall inside the SLO window and at most 5 minutes ahead. `pushSloEvents(api, project, slo, events)` sends once without batching.

## `@shelbyb/daywalker-sdk/deploys`

```ts
import { recordDeploy } from "@shelbyb/daywalker-sdk/deploys";

await recordDeploy(api, "web", { environment: "production", release: "web@2.4.0", sha: process.env.GITHUB_SHA });
```

`POST /api/v1/projects/{project}/deploys` (scope `deploy:create`) with `environment` (required), `release`, `sha`, `ref`, `url`, `description`, `deployedAt`.
