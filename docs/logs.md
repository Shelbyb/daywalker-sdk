# Logs: `@shelbyb/daywalker-sdk/logs`

Ship structured logs to `POST {host}/logs/ingest` with a log source's ingest token (`Authorization: Bearer dpl_…`).

```ts
import { createLogger } from "@shelbyb/daywalker-sdk/logs";

const logger = createLogger({ host: "https://devpulse.example.com", token: process.env.DEVPULSE_LOG_TOKEN!, service: "api" });
logger.info("user signed in", { userId: 42 });
logger.child({ requestId }).error("db timeout", { ms: 5003 });
await logger.shutdown(); // flush before exit
```

- Levels: `trace`, `debug`, `info`, `warn`, `error`, `fatal`; `minLevel` (default `debug`) drops lower ones.
- Entries are queued and sent as a JSON array when `flushAt` (100) entries are queued, every `flushIntervalMs` (5 s), or on `flush()`/`shutdown()`. `log()` never throws.
- Limits match DevPulse (`LOG_LIMITS`): requests are split under `maxBatchBytes` (1 MB, never above the server's 5 MB) and 5,000 entries; messages over 32 KB are clipped; attribute objects over 16 KB become `{ "devpulse.truncated": true, "devpulse.original_size": n }`, as the server does. Beyond `maxQueueSize` (10,000) the oldest entries are dropped (`logger.dropped`).
- 429 (honoring `Retry-After`), 5xx and network errors are retried `maxRetries` (2) times; other errors (401, 413) drop the batch. Failures go to `onError`.
- `consoleAdapter(logger, { passthrough: console })` returns a console-shaped object. `pinoDestination(logger)` is a pino destination: `pino({}, pinoDestination(logger))`. `logger.raw(obj)` sends an object as is.
