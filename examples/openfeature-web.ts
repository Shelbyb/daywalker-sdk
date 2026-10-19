// OpenFeature in the browser.
import { OpenFeature } from "@openfeature/web-sdk";
import { DevPulseWebProvider } from "@shelbyb/daywalker-sdk/openfeature/web";

await OpenFeature.setContext({ targetingKey: "user-123" });
await OpenFeature.setProviderAndWait(new DevPulseWebProvider("YOUR_CLIENT_SIDE_ID", { baseUrl: "https://devpulse.example.com" }));
console.log(OpenFeature.getClient().getBooleanValue("new-checkout", false));
