// Validate an incoming API token with Daywalker Auth (Node, Bun, Deno, edge).
// Env: DAYWALKER_API_KEY, DAYWALKER_SERVICE_SLUG, DAYWALKER_SIGNING_KEY (from `npx daywalker init`).
import { Daywalker, DaywalkerRateLimitError } from "@shelbyb/daywalker-sdk";

const client = new Daywalker({ serviceSlug: process.env.DAYWALKER_SERVICE_SLUG });

export async function authenticate(req: Request) {
  const result = await client.validateToken(req.headers.get("x-api-token") ?? "");
  if (!result.ok) return new Response(result.message, { status: result.status });
  return Response.json({ tokenId: result.data.tokenId });
}

export async function requireAuth(token: string) {
  try {
    return await client.requireValidToken(token);
  } catch (err) {
    if (err instanceof DaywalkerRateLimitError) console.warn(`Rate limited, retry after ${err.retryAfter}s`);
    throw err;
  }
}
