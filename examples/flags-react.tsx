"use client";
// React provider and hooks. Env: NEXT_PUBLIC_DEVPULSE_CLIENT_ID, NEXT_PUBLIC_DEVPULSE_URL.
import type { ReactNode } from "react";
import { DevPulseProvider, useFlag, useTrack } from "@shelbyb/daywalker-sdk/flags/react";

export function Providers({ userId, children }: { userId: string; children: ReactNode }) {
  return (
    <DevPulseProvider
      clientSideId={process.env.NEXT_PUBLIC_DEVPULSE_CLIENT_ID!}
      context={{ kind: "user", key: userId }}
      options={{ baseUrl: process.env.NEXT_PUBLIC_DEVPULSE_URL! }}
    >
      {children}
    </DevPulseProvider>
  );
}

export function CheckoutButton() {
  const newCheckout = useFlag("new-checkout", false);
  const track = useTrack();
  return <button onClick={() => track("checkout-clicked")}>{newCheckout ? "Pay now" : "Checkout"}</button>;
}
