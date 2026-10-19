// Page the on-call engineer (Events API v2). Env: DEVPULSE_URL, DEVPULSE_ROUTING_KEY.
import { createOncall } from "@shelbyb/daywalker-sdk/oncall";

const oncall = createOncall({ host: process.env.DEVPULSE_URL!, routingKey: process.env.DEVPULSE_ROUTING_KEY! });

const { dedupKey } = await oncall.trigger({ summary: "Primary DB disk 95% full", severity: "critical", source: "db-1", dedupKey: "db-1-disk" });
await oncall.acknowledge(dedupKey);
await oncall.resolve(dedupKey);
