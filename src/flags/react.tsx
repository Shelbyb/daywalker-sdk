"use client";

import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
import { createClient, type ClientOptions, type ContextInput, type DevPulseClient, type EvaluationDetail, type FlagSet, type FlagValue } from "./client.js";

export type { ClientOptions, ContextInput, DevPulseClient, FlagSet, FlagValue };

const ClientContext = createContext<DevPulseClient | null>(null);

export interface DevPulseProviderProps {
  clientSideId: string;
  context: ContextInput;
  options: ClientOptions;
  /** Use an existing client instead of creating one. */
  client?: DevPulseClient;
  children: ReactNode;
}

const isBrowser = typeof window !== "undefined";

/**
 * Provides a DevPulse client to the tree. On the server (SSR/RSC streaming) and during the
 * first client render, an offline client serves `options.bootstrap` and makes no requests, so
 * hydration matches the server HTML. The live client is created (and closed) in an effect,
 * which keeps StrictMode's simulated unmount from leaving a closed client behind. Changing
 * `context` calls identify().
 */
export function DevPulseProvider({ clientSideId, context, options, client: external, children }: DevPulseProviderProps) {
  const contextJson = JSON.stringify(context);
  // Render-time stand-in: no network, timers or listeners, so creating it during render is safe.
  // No localStorage cache either, so the first client render matches the server HTML.
  const [placeholder] = useState(() => createClient(clientSideId, context, { ...options, offline: true, sendEvents: false, cache: false }));
  const [owned, setOwned] = useState<DevPulseClient | null>(null);
  const latest = useRef({ contextJson, options });
  latest.current = { contextJson, options };

  useEffect(() => {
    if (external || !isBrowser) return;
    const c = createClient(clientSideId, JSON.parse(latest.current.contextJson) as ContextInput, latest.current.options);
    setOwned(c);
    return () => {
      void c.close();
      setOwned((cur) => (cur === c ? null : cur));
    };
  }, [external, clientSideId]);

  const live = external ?? owned;
  const seen = useRef<{ client: DevPulseClient | null; contextJson: string }>({ client: null, contextJson });
  useEffect(() => {
    if (!live || live.isClosed) return;
    const prev = seen.current;
    seen.current = { client: live, contextJson };
    // A client we just created already has the current context; an injected one is taken as is.
    const changed = prev.client === live ? prev.contextJson !== contextJson : live === owned && JSON.stringify(live.getContext()) !== contextJson;
    if (changed) void live.identify(JSON.parse(contextJson) as ContextInput).catch(() => undefined);
  }, [live, owned, contextJson]);

  return <ClientContext.Provider value={live ?? placeholder}>{children}</ClientContext.Provider>;
}

export function useDevPulseClient(): DevPulseClient {
  const client = useContext(ClientContext);
  if (!client) throw new Error("useDevPulseClient must be used inside <DevPulseProvider>");
  return client;
}

/** Current value of one flag; re-renders only when that flag changes. */
export function useFlag<T extends FlagValue>(key: string, defaultValue: T): T {
  return useFlagDetail(key, defaultValue).value;
}

export function useFlagDetail<T extends FlagValue>(key: string, defaultValue: T): EvaluationDetail<T> {
  const client = useDevPulseClient();
  const defaultJson = JSON.stringify(defaultValue);
  const subscribe = useMemo(() => (cb: () => void) => client.on(`change:${key}`, cb), [client, key]);
  // Snapshot is the serialized value so useSyncExternalStore sees stable identities.
  // Own keys only: `allFlags()["constructor"]` would otherwise resolve to Object.prototype's.
  const snapshot = () => {
    const flags = client.allFlags();
    return JSON.stringify(Object.hasOwn(flags, key) ? flags[key] : null);
  };
  const serialized = useSyncExternalStore(subscribe, snapshot, snapshot);
  const detail = useMemo(() => client.peekVariationDetail(key, JSON.parse(defaultJson) as T), [client, key, defaultJson, serialized]); // eslint-disable-line react-hooks/exhaustive-deps
  // Record the evaluation (analytics) after commit, once per distinct result: renders can be
  // repeated or thrown away (StrictMode, concurrent rendering), effects re-run in StrictMode.
  const recorded = useRef<unknown>(null);
  useEffect(() => {
    if (recorded.current === detail) return;
    recorded.current = detail;
    client.recordEvaluation(key, JSON.parse(defaultJson) as T, detail);
  }, [client, key, defaultJson, detail]);
  return detail;
}

/** All flag values; re-renders when any flag changes. */
export function useFlags(): Record<string, FlagValue> {
  const client = useDevPulseClient();
  const subscribe = useMemo(() => (cb: () => void) => client.on("change", cb), [client]);
  const json = useSyncExternalStore(subscribe, () => JSON.stringify(client.allFlags()), () => JSON.stringify(client.allFlags()));
  return useMemo(() => JSON.parse(json) as Record<string, FlagValue>, [json]);
}

/** True once flags have loaded (always true when bootstrapped). */
export function useFlagsReady(): boolean {
  const client = useDevPulseClient();
  const subscribe = useMemo(() => (cb: () => void) => client.on("ready", cb), [client]);
  return useSyncExternalStore(subscribe, () => client.isInitialized, () => client.isInitialized);
}

/** Track a custom event for metrics and experiments. Stable across renders (safe in effect deps). */
export function useTrack() {
  const client = useDevPulseClient();
  return useCallback((key: string, data?: unknown, metricValue?: number) => client.track(key, data, metricValue), [client]);
}
