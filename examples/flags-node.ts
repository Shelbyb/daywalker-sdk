// Server-side flags (Node, Bun, Deno, Workers). Env: DEVPULSE_SDK_KEY, DEVPULSE_URL.
import { init } from "@shelbyb/daywalker-sdk/flags/node";

export const flags = init(process.env.DEVPULSE_SDK_KEY!, { baseUrl: process.env.DEVPULSE_URL! });
await flags.waitForInitialization({ timeoutMs: 5000 });

const context = { kind: "user", key: "user-123", plan: "pro" };
if (await flags.variation("new-checkout", context, false)) console.log("new checkout");
flags.track("checkout-completed", context, undefined, 49);
