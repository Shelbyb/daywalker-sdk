// Product analytics in the browser.
import { createAnalytics } from "@shelbyb/daywalker-sdk/analytics";

const analytics = createAnalytics({ writeKey: "dpa_YOUR_WRITE_KEY", host: "https://devpulse.example.com" });
analytics.capture("project_created", { template: "nextjs" });
analytics.identify("user-123", { plan: "pro" });
