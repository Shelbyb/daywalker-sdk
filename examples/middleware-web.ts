// Web-standard middleware: Hono (`app.use("/api/*", auth)`) or a plain fetch handler (Bun.serve, Deno.serve, Workers).
import { daywalkerAuth } from "@shelbyb/daywalker-sdk/middleware";

const auth = daywalkerAuth({ serviceSlug: process.env.DAYWALKER_SERVICE_SLUG });

export default {
  async fetch(req: Request): Promise<Response> {
    // The middleware answers 401/429/503 itself; otherwise it calls next().
    const denied = await auth(req, async () => undefined);
    return denied ?? Response.json({ ok: true });
  },
};
