// Call Daywalker Auth with a DPoP access token and an RFC 9421 signed request.
import { daywalker } from "@shelbyb/daywalker-sdk";

export async function validateViaFetch(token: string) {
  const res = await daywalker.fetch("/api/v1/tokens/validate", {
    method: "POST",
    body: { token },
    idempotencyKey: crypto.randomUUID(),
  });
  return res.json();
}
