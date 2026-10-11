# @shelbyb/daywalker-sdk/flags/react

React provider and hooks for [DevPulse](https://github.com/shelbyb/devpulse) feature flags. Components re-render when the flags they read change, in real time.

```bash
npm install @shelbyb/daywalker-sdk
```

```tsx
"use client";
import { DevPulseProvider, useFlag, useTrack } from "@shelbyb/daywalker-sdk/flags/react";

export function Providers({ context, bootstrap, hash, children }) {
  return (
    <DevPulseProvider
      clientSideId={process.env.NEXT_PUBLIC_DEVPULSE_CLIENT_ID!}
      context={context}
      options={{ baseUrl: process.env.NEXT_PUBLIC_DEVPULSE_URL!, bootstrap, hash }}
    >
      {children}
    </DevPulseProvider>
  );
}

function Checkout() {
  const newCheckout = useFlag("new-checkout", false);
  const track = useTrack();
  return newCheckout ? <NewCheckout onDone={(total) => track("checkout-completed", undefined, total)} /> : <OldCheckout />;
}
```

- **SSR / React Server Components:** pass `bootstrap` from `@shelbyb/daywalker-sdk/flags/node`'s `allFlagsState(context, { clientSideOnly: true }).toJSON()`. The server render and first client render then match, with no loading flicker. No network connection is opened during server rendering.
- Changing the `context` prop calls `identify()`.

Hooks: `useFlag(key, default)`, `useFlagDetail(key, default)`, `useFlags()`, `useFlagsReady()`, `useTrack()`, `useDevPulseClient()`.
