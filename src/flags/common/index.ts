export { SseParser, SseClient, SseError, backoffDelay, type SseEvent, type SseClientOptions } from "./sse.js";
export { EventProcessor, noopLogger, type EventProcessorOptions, type Logger } from "./events.js";

/** Encode a context for URLs (base64url JSON), matching the DevPulse SDK endpoints. */
export function encodeContext(context: unknown): string {
  const json = JSON.stringify(context);
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export const SDK_VERSION = "0.1.0";
