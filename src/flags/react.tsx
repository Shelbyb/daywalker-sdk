
import { createContext, useContext, useEffect, useMemo, useRef, useState, useSyncExternalStore, type ReactNode } from "react";
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
 * Provides a DevPulse client to the tree. On the server (SSR/RSC streaming)
 * no network connection is opened; flags come from `options.bootstrap`, so the
 * first client render matches the server HTML. Changing `context` calls identify().
 */
export function DevPulseProvider({ clientSideId, context, options, client: external, children }: DevPulseProviderProps) {
  const [client] = useState(() => external ?? createClient(clientSideId, context, isBrowser ? options : { ...options, streaming: false, sendEvents: false, bootstrap: options.bootstrap ?? {} }));
  const contextJson = JSON.stringify(context);
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    void client.identify(JSON.parse(contextJson) as ContextInput);
  }, [client, contextJson]);
  useEffect(() => () => void (!external && client.close()), [client, external]);
  return <ClientContext.Provider value={client}>{children}</ClientContext.Provider>;
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
  const snapshot = () => JSON.stringify(client.allFlags()[key] ?? null);
  const serialized = useSyncExternalStore(subscribe, snapshot, snapshot);
  // Record the evaluation (analytics) once per distinct value.
  return useMemo(() => client.variationDetail(key, JSON.parse(defaultJson) as T), [client, key, defaultJson, serialized]); // eslint-disable-line react-hooks/exhaustive-deps
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

/** Track a custom event for metrics and experiments. */
export function useTrack() {
  const client = useDevPulseClient();
  return (key: string, data?: unknown, metricValue?: number) => client.track(key, data, metricValue);
}
