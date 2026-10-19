import { createHmac } from "node:crypto";
import { readFileSync } from "node:fs";
import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { isEventType, signWebhook, verifyWebhook, WebhookVerificationError, type WebhookErrorCode } from "../src/webhooks/index.js";

type Case = { name: string; secret: string; id: string; timestamp: number; now: number; body: string; signature: string; valid: boolean; parse?: false; error?: WebhookErrorCode };
const vectors = JSON.parse(readFileSync(new URL("../test-vectors/webhooks-standard.json", import.meta.url), "utf8")) as { cases: Case[] };

async function code(p: Promise<unknown>): Promise<string> {
  try {
    await p;
  } catch (err) {
    expect(err instanceof WebhookVerificationError).toBe(true);
    return (err as WebhookVerificationError).code;
  }
  throw new Error("should have failed");
}

const SECRET = vectors.cases[1]!.secret;
const body = JSON.stringify({ type: "cron.failed", timestamp: "2026-10-19T12:00:00Z", data: { check: "nightly" } });
const now = 1_792_411_200;
const hdrs = async (over: Record<string, string> = {}) => ({ "webhook-id": "msg_1", "webhook-timestamp": String(now), "webhook-signature": await signWebhook(SECRET, "msg_1", now, body), ...over });

describe("webhooks: conformance vectors", () => {
  for (const c of vectors.cases) {
    it(c.name, async () => {
      if (c.valid) {
        const sig = c.signature.split(" ").at(-1)!;
        expect(await signWebhook(c.secret, c.id, c.timestamp, c.body)).toBe(sig);
        const key = Buffer.from(c.secret.slice(6), "base64");
        expect(sig).toBe(`v1,${createHmac("sha256", key).update(`${c.id}.${c.timestamp}.${c.body}`).digest("base64")}`);
      }
      const headers = new Headers({ "webhook-id": c.id, "webhook-timestamp": String(c.timestamp), "webhook-signature": c.signature });
      const p = verifyWebhook({ secret: c.secret, headers, body: c.body, now: c.now * 1000 });
      if (c.valid && c.parse !== false) expect((await p).type).toBe(JSON.parse(c.body).type);
      else if (c.valid) expect(await code(p)).toBe("INVALID_PAYLOAD");
      else expect(await code(p)).toBe(c.error!);
    });
  }
});

describe("webhooks: verifyWebhook", () => {
  it("accepts plain-object headers (any case, arrays), bytes and ArrayBuffer bodies", async () => {
    const h = await hdrs();
    const node = { "Webhook-Id": h["webhook-id"], "WEBHOOK-TIMESTAMP": [h["webhook-timestamp"]], "webhook-signature": h["webhook-signature"] };
    const bytes = new TextEncoder().encode(body);
    expect((await verifyWebhook({ secret: SECRET, headers: node, body: bytes, now: now * 1000 })).data).toEqual({ check: "nightly" });
    expect((await verifyWebhook({ secret: SECRET, headers: h, body: bytes.buffer, now: now * 1000 })).type).toBe("cron.failed");
  });

  it("supports secret rotation (array of secrets) and secrets without the whsec_ prefix", async () => {
    const other = `whsec_${Buffer.alloc(24, 1).toString("base64")}`;
    expect((await verifyWebhook({ secret: [other, SECRET.slice(6)], headers: await hdrs(), body, now: now * 1000 })).type).toBe("cron.failed");
    expect(await code(verifyWebhook({ secret: [other], headers: await hdrs(), body, now: now * 1000 }))).toBe("INVALID_SIGNATURE");
    expect(await code(verifyWebhook({ secret: [], headers: await hdrs(), body, now: now * 1000 }))).toBe("INVALID_SECRET");
  });

  it("rejects missing headers, bad timestamps, bad secrets, malformed signatures and non-events", async () => {
    const h = await hdrs();
    expect(await code(verifyWebhook({ secret: SECRET, headers: { ...h, "webhook-id": "" }, body, now: now * 1000 }))).toBe("MISSING_HEADERS");
    expect(await code(verifyWebhook({ secret: SECRET, headers: new Headers(), body }))).toBe("MISSING_HEADERS");
    expect(await code(verifyWebhook({ secret: SECRET, headers: { ...h, "webhook-timestamp": "12.5" }, body }))).toBe("INVALID_TIMESTAMP");
    expect(await code(verifyWebhook({ secret: SECRET, headers: h, body }))).toBe("TIMESTAMP_OUT_OF_TOLERANCE");
    expect((await verifyWebhook({ secret: SECRET, headers: h, body, now: (now + 3000) * 1000, toleranceSeconds: 3600 })).type).toBe("cron.failed");
    expect(await code(verifyWebhook({ secret: "whsec_!!!", headers: h, body, now: now * 1000 }))).toBe("INVALID_SECRET");
    expect(await code(verifyWebhook({ secret: "whsec_c2hvcnQ=", headers: h, body, now: now * 1000 }))).toBe("INVALID_SECRET");
    expect(await code(verifyWebhook({ secret: SECRET, headers: { ...h, "webhook-signature": "v1,%%% v1 garbage" }, body, now: now * 1000 }))).toBe("INVALID_SIGNATURE");
    const bad = async (b: string) => verifyWebhook({ secret: SECRET, headers: { ...h, "webhook-signature": await signWebhook(SECRET, "msg_1", now, b) }, body: b, now: now * 1000 });
    expect(await code(bad("not json"))).toBe("INVALID_PAYLOAD");
    expect(await code(bad("[1]"))).toBe("INVALID_PAYLOAD");
    expect(await code(bad("null"))).toBe("INVALID_PAYLOAD");
  });

  it("isEventType matches exact types and trailing wildcards", () => {
    const e = { type: "flag.updated", timestamp: "", data: {} };
    expect(isEventType(e, "flag.updated")).toBe(true);
    expect(isEventType(e, "flag.*")).toBe(true);
    expect(isEventType(e, "slo.*")).toBe(false);
  });
});
