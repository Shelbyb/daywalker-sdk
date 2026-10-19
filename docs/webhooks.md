# Webhooks: `@shelbyb/daywalker-sdk/webhooks`

Verify DevPulse webhook deliveries. DevPulse signs every delivery with [Standard Webhooks](https://www.standardwebhooks.com): `webhook-id`, `webhook-timestamp` (Unix seconds) and `webhook-signature: v1,<base64>` where the signature is HMAC-SHA256 over `${id}.${timestamp}.${rawBody}` with the base64-decoded part of the endpoint's `whsec_…` secret. WebCrypto only; runs anywhere.

```ts
import { verifyWebhook, WebhookVerificationError } from "@shelbyb/daywalker-sdk/webhooks";

export async function POST(req: Request) {
  const body = await req.text(); // raw body, before any JSON parsing
  try {
    const event = await verifyWebhook({ secret: process.env.DEVPULSE_WEBHOOK_SECRET!, headers: req.headers, body });
    // event: { type: "flag.updated", timestamp: "…", data: { … } }
    return new Response(null, { status: 204 });
  } catch (err) {
    if (err instanceof WebhookVerificationError) return new Response(err.code, { status: 400 });
    throw err;
  }
}
```

- `headers` is a `Headers` object or a plain object (Express/Node `req.headers`, any case).
- `body` is the raw body as a string, `Uint8Array` or `ArrayBuffer`. With Express use `express.raw({ type: "application/json" })`.
- `secret` may be an array while you rotate secrets. Several space-separated signatures in the header are accepted; any match is enough. Comparison is constant time.
- `toleranceSeconds` (default 300) rejects old or future timestamps (replay protection). Also de-duplicate on `webhook-id`: retries reuse it.
- Error codes: `MISSING_HEADERS`, `INVALID_TIMESTAMP`, `TIMESTAMP_OUT_OF_TOLERANCE`, `INVALID_SECRET`, `INVALID_SIGNATURE`, `INVALID_PAYLOAD`.
- `signWebhook(secret, id, timestamp, body)` produces the header value (tests, local replays). `isEventType(event, "flag.*")` matches types with a trailing wildcard.

Event types: `ping`, `flag.*` (`created`, `updated`, `archived`, `deleted`, `approval_requested`, `rollout_*`), `segment.updated`, `experiment.*`, `incident.*`, `maintenance.*`, `status_page.*`, `error.*`, `secret.*`, `cron.*`, `slo.*`, `changelog.*`.

Conformance vectors: [`test-vectors/webhooks-standard.json`](../test-vectors/webhooks-standard.json) (includes the Standard Webhooks spec example).
