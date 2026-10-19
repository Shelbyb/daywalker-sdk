// Verify a DevPulse webhook (Standard Webhooks) in any fetch-style handler. Env: DEVPULSE_WEBHOOK_SECRET (whsec_...).
import { verifyWebhook, WebhookVerificationError } from "@shelbyb/daywalker-sdk/webhooks";

type FlagUpdated = { key: string; project: string };

export async function POST(req: Request) {
  const body = await req.text(); // the raw body: verify before parsing
  try {
    const event = await verifyWebhook<FlagUpdated>({ secret: process.env.DEVPULSE_WEBHOOK_SECRET!, headers: req.headers, body });
    if (event.type === "flag.updated") console.log("flag changed:", event.data.key);
    return new Response(null, { status: 204 });
  } catch (err) {
    if (err instanceof WebhookVerificationError) return new Response(err.code, { status: 400 });
    throw err;
  }
}
