// Record a deploy marker from CI. Env: DEVPULSE_URL, DEVPULSE_CLIENT_ID, DEVPULSE_CLIENT_SECRET (scope deploy:create), GITHUB_SHA.
import { createApiClient } from "@shelbyb/daywalker-sdk/api";
import { recordDeploy } from "@shelbyb/daywalker-sdk/deploys";

const api = createApiClient({ host: process.env.DEVPULSE_URL!, clientId: process.env.DEVPULSE_CLIENT_ID!, clientSecret: process.env.DEVPULSE_CLIENT_SECRET!, scope: "deploy:create" });
await recordDeploy(api, "web", { environment: "production", release: "web@2.4.0", sha: process.env.GITHUB_SHA });
