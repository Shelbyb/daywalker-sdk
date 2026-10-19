// Management API (/api/v1) with OAuth client credentials. Env: DEVPULSE_URL, DEVPULSE_CLIENT_ID, DEVPULSE_CLIENT_SECRET.
import { ApiProblemError, createApiClient } from "@shelbyb/daywalker-sdk/api";

const api = createApiClient({ host: process.env.DEVPULSE_URL!, clientId: process.env.DEVPULSE_CLIENT_ID!, clientSecret: process.env.DEVPULSE_CLIENT_SECRET! });

for await (const project of api.paginate<{ key: string; name: string }>("/api/v1/projects")) console.log(project.key);

try {
  const { data, etag } = await api.get<{ key: string; on: boolean }>("/api/v1/projects/web/flags/new-checkout");
  await api.patch("/api/v1/projects/web/flags/new-checkout", { on: !data.on }, { ifMatch: etag ?? undefined });
} catch (err) {
  if (err instanceof ApiProblemError && err.isPreconditionFailed) console.log("changed by someone else, retry");
  else throw err;
}
