// Ship structured logs. Env: DEVPULSE_URL, DEVPULSE_LOG_TOKEN (dpl_...).
import { consoleAdapter, createLogger, pinoDestination } from "@shelbyb/daywalker-sdk/logs";

const logger = createLogger({ host: process.env.DEVPULSE_URL!, token: process.env.DEVPULSE_LOG_TOKEN!, service: "api", minLevel: "info" });

logger.info("user signed in", { userId: 42 });
logger.child({ requestId: "req-1" }).error("db timeout", { ms: 5003 });

// console-style: const log = consoleAdapter(logger, { passthrough: console });
export const log = consoleAdapter(logger, { passthrough: console });
// pino: pino({}, pinoDestination(logger))
export const destination = pinoDestination(logger);

await logger.shutdown(); // flush before exit
