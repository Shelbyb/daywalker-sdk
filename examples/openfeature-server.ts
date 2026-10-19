// OpenFeature on the server. Env: DEVPULSE_SDK_KEY, DEVPULSE_URL.
import { OpenFeature } from "@openfeature/server-sdk";
import { DevPulseServerProvider } from "@shelbyb/daywalker-sdk/openfeature/server";

await OpenFeature.setProviderAndWait(new DevPulseServerProvider(process.env.DEVPULSE_SDK_KEY!, { baseUrl: process.env.DEVPULSE_URL! }));
const enabled = await OpenFeature.getClient().getBooleanValue("new-checkout", false, { targetingKey: "user-123", plan: "pro" });
console.log(enabled);
