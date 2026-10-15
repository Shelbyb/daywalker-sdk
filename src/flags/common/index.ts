export { SseParser, SseClient, SseError, backoffDelay, DEFAULT_MAX_EVENT_SIZE, MIN_SERVER_RETRY_MS, type SseEvent, type SseClientOptions } from "./sse.js";
export { EventProcessor, noopLogger, chunkEvents, MAX_EVENTS_PER_REQUEST, MAX_REQUEST_BYTES, KEEPALIVE_MAX_BYTES, type EventProcessorOptions, type Logger } from "./events.js";

/** Encode a context for URLs (base64url JSON), matching the DevPulse SDK endpoints. */
export function encodeContext(context: unknown): string {
  const json = JSON.stringify(context);
  const bytes = new TextEncoder().encode(json);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export { SDK_VERSION } from "./version.js";
