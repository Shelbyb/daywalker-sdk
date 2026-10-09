import { daywalker, type Daywalker } from "./client.js";
import { KEYS_PATH } from "./signing.js";

interface Req { method?: string; path?: string; url?: string }
interface Res {
  setHeader(name: string, value: string): unknown;
  statusCode?: number;
  end(body?: string): unknown;
}

/**
 * Express / Connect / Node http middleware that serves /.well-known/daywalker-keys.json.
 *
 *   app.use(daywalkerKeys());
 */
export function daywalkerKeys(client: Daywalker = daywalker()) {
  return (req: Req, res: Res, next?: () => void) => {
    const path = req.path ?? (req.url ?? "").split("?")[0];
    if ((req.method ?? "GET") === "GET" && path === KEYS_PATH) {
      res.statusCode = 200;
      res.setHeader("Content-Type", "application/json");
      res.setHeader("Cache-Control", "public, max-age=300");
      res.end(JSON.stringify(client.keys()));
      return;
    }
    next?.();
  };
}
