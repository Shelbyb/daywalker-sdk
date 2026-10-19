// Feature flags in the browser, with live updates.
import { createClient } from "@shelbyb/daywalker-sdk/flags";

const flags = createClient(
  "YOUR_CLIENT_SIDE_ID", // DevPulse: Project -> Environments & keys (not a secret)
  { kind: "user", key: "user-123", plan: "pro" },
  { baseUrl: "https://devpulse.example.com" },
);

await flags.waitForInitialization({ timeoutMs: 3000 });
if (flags.variation("new-checkout", false)) document.body.classList.add("new-checkout");
flags.on("change:new-checkout", (on: unknown) => document.body.classList.toggle("new-checkout", Boolean(on)));
