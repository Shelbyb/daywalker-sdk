// Express or Connect: `app.use("/api", auth)`; on success the validated payload is on `req.auth`.
import { daywalkerAuth } from "@shelbyb/daywalker-sdk/express";

const auth = daywalkerAuth({ serviceSlug: process.env.DAYWALKER_SERVICE_SLUG });

// Typed against the middleware itself so this compiles without express installed.
export function mount(app: { use(path: string, middleware: typeof auth): unknown }) {
  app.use("/api", auth);
}
