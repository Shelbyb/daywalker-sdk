import { daywalker, type Daywalker } from "./client.js";

/**
 * Next.js App Router route handler for /.well-known/daywalker-keys.json.
 *
 *   // app/.well-known/daywalker-keys.json/route.ts
 *   export { GET, dynamic } from "@shelbyb/daywalker-sdk/next";
 */
export const dynamic = "force-dynamic";

export function keysRouteHandler(client: Daywalker = daywalker()) {
  return function GET(): Response {
    return Response.json(client.keys(), { headers: { "Cache-Control": "public, max-age=300" } });
  };
}

export const GET = (): Response => keysRouteHandler()();
