// app/api/protected/route.ts: a route handler that only runs for valid tokens.
import { withDaywalkerAuth } from "@shelbyb/daywalker-sdk/next";

export const POST = withDaywalkerAuth(async (_req, { auth }) => Response.json({ hello: auth.serviceSlug }));
