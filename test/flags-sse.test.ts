import { describe, it } from "node:test";
import { expect } from "./helpers/expect.js";
import { EventProcessor, SseParser, encodeContext } from "../src/flags/common/index.js";

const parse = (...chunks: string[]) => {
  const p = new SseParser();
  return chunks.flatMap((c) => p.feed(c));
};

describe("SseParser (WHATWG HTML §9.2.6)", () => {
  it("parses multi-line data and ignores comments", () => {
    // Spec example: "data: YHOO\ndata: +2\ndata: 10\n\n"
    expect(parse(": test stream\n\ndata: first event\nid: 1\n\ndata:second event\nid\n\ndata:  third event\n\n")).toEqual([
      { type: "message", data: "first event", lastEventId: "1" },
      { type: "message", data: "second event", lastEventId: "" },
      { type: "message", data: " third event", lastEventId: "" },
    ]);
    expect(parse("data: YHOO\ndata: +2\ndata: 10\n\n")).toEqual([{ type: "message", data: "YHOO\n+2\n10", lastEventId: "" }]);
  });

  it("handles empty data fields as in the spec example", () => {
    expect(parse("data\n\ndata\ndata\n\ndata:\n")).toEqual([
      { type: "message", data: "", lastEventId: "" },
      { type: "message", data: "\n", lastEventId: "" },
    ]);
  });

  it("supports CRLF, CR and LF and chunk boundaries anywhere (including mid-CRLF)", () => {
    expect(parse("event: put\r", "\ndata: {\"a\":1}\r\n\r\n", "event: patch\rdata: x\r\r")).toEqual([
      { type: "put", data: '{"a":1}', lastEventId: "" },
      { type: "patch", data: "x", lastEventId: "" },
    ]);
    expect(parse("da", "ta: sp", "lit\n", "\n")).toEqual([{ type: "message", data: "split", lastEventId: "" }]);
  });

  it("strips a leading BOM, reads retry, ignores ids with NUL", () => {
    const p = new SseParser();
    expect(p.feed("﻿retry: 2500\nid: a\0b\ndata: x\n\n")).toEqual([{ type: "message", data: "x", lastEventId: "" }]);
    expect(p.retry).toBe(2500);
    p.feed("retry: soon\n");
    expect(p.retry).toBe(2500);
  });

  it("resets the event type after dispatch", () => {
    expect(parse("event: a\ndata: 1\n\ndata: 2\n\n").map((e) => e.type)).toEqual(["a", "message"]);
  });
});

describe("EventProcessor", () => {
  it("redacts private attributes and summarizes evaluations", async () => {
    const sent: unknown[] = [];
    const ep = new EventProcessor({
      url: "http://x/events",
      privateAttributes: ["email"],
      flushIntervalMs: 1_000_000,
      fetch: (async (_u: string, init: { body: string }) => {
        sent.push(...JSON.parse(init.body));
        return new Response(null, { status: 202 });
      }) as unknown as typeof fetch,
    });
    const context = { key: "u1", email: "a@b.c", name: "Ada", _meta: { privateAttributes: ["name"] } };
    for (let i = 0; i < 3; i++) ep.recordEvaluation({ key: "f", context, value: true, default: false, variation: 0, version: 4 });
    ep.recordEvaluation({ key: "missing", context, value: false, default: false, variation: null });
    ep.track("purchase", context, undefined, 9.5);
    await ep.close();
    const index = sent.find((e) => (e as { kind: string }).kind === "index") as { context: Record<string, unknown> };
    expect(index.context).toEqual({ key: "u1", redactedAttributes: ["email", "name"] });
    const summary = sent.find((e) => (e as { kind: string }).kind === "summary") as { features: Record<string, { counters: unknown[] }> };
    expect(summary.features.f?.counters).toEqual([{ variation: 0, version: 4, value: true, count: 3 }]);
    expect(summary.features.missing?.counters).toEqual([{ unknown: true, value: false, count: 1 }]);
    expect(sent.filter((e) => (e as { kind: string }).kind === "index")).toHaveLength(1);
    expect(sent.find((e) => (e as { kind: string }).kind === "custom")).toMatchObject({ key: "purchase", contextKeys: { user: "u1" }, metricValue: 9.5 });
  });
});

describe("encodeContext", () => {
  it("produces base64url JSON that round-trips unicode", () => {
    const enc = encodeContext({ key: "ü/+?" });
    expect(enc).not.toMatch(/[+/=]/);
    expect(JSON.parse(Buffer.from(enc, "base64url").toString("utf8"))).toEqual({ key: "ü/+?" });
  });
});
