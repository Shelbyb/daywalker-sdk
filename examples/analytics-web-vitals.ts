// Real-user Web Vitals (LCP, CLS, INP, FCP, TTFB) sent to DevPulse RUM.
import { createAnalytics } from "@shelbyb/daywalker-sdk/analytics";

const analytics = createAnalytics({ writeKey: "dpa_YOUR_WRITE_KEY", host: "https://devpulse.example.com", autocapturePageviews: false });
const stop = analytics.captureWebVitals({ sampleRate: 0.5, release: "web@2.4.0", environment: "production" });
addEventListener("beforeunload", () => stop());
