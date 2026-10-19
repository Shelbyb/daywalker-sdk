# @shelbyb/daywalker-sdk/analytics

Product analytics for browsers and Node: events, automatic page views (including client-side navigation), sessions, identify, super properties and feature-flag properties.

```sh
npm install @shelbyb/daywalker-sdk
```

```ts
import { createAnalytics } from "@shelbyb/daywalker-sdk/analytics";

const analytics = createAnalytics({ writeKey: "dpa_…", host: "https://devpulse.example.com" });

analytics.capture("project_created", { template: "nextjs" });
analytics.identify(user.id, { email: user.email, plan: user.plan }); // merges the anonymous history
analytics.register({ app_version: "2.4.0" }); // sent with every event
analytics.reset(); // on logout
```

Server-side (Node), pass who did it and flush before exit:

```ts
const analytics = createAnalytics({ writeKey: process.env.DEVPULSE_WRITE_KEY!, host: "https://devpulse.example.com" });
analytics.capture("invoice_paid", { amount: 49 }, { distinctId: customer.id });
await analytics.shutdown();
```

Add each flag's value to events (for breakdowns by variation) with `flags: client` where `client` is a `@shelbyb/daywalker-sdk/flags` instance (anything with `allFlags()`).

Options: `autocapturePageviews` (default true), `flushAt` (20), `flushInterval` (2s browser / 10s Node), `maxQueueSize` (1000), `persistence` (`localStorage` | `memory`), `sessionTimeoutMinutes` (30), `respectDoNotTrack`, `optedOut` (consent; opting out also drops events already queued), `captureFullUrls` (default false: URLs drop the fragment and all query parameters except `utm_*`, `gclid`, `fbclid`, `ref`), `sanitizePath` (rewrite paths that carry secrets, e.g. `(p) => p.replace(/^\/reset\/[^/]+/, "/reset/:token")`), `onError`. `host` must be `https://` except on localhost.

Events are sent to `POST {host}/a/batch`, which also accepts PostHog's capture format.

## Web Vitals

`autocaptureWebVitals: true` (or `{ sampleRate, release, environment, path }`), or `analytics.captureWebVitals(options)` which returns a stop function, measures LCP, CLS, INP, FCP, TTFB and page load and sends them to `POST {host}/a/rum` when the page is hidden. Skipped for Do Not Track, Global Privacy Control and while opted out; no-op outside browsers. See the README's Web Vitals section.

Examples: [`examples/`](../examples/README.md).
