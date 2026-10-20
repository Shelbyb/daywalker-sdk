/**
 * React bindings. Needs `react-dom` (not a dependency of this package): the suite skips when
 * it can't be resolved. Client rendering runs against a tiny fake DOM, enough for React to
 * mount text in <span>s.
 */
import { describe, it } from "node:test";
import { createElement as h, StrictMode, act, type ReactNode } from "react";
import { expect } from "./helpers/expect.js";

// Optional: loaded by name so this file type-checks without react-dom installed.
const load = (name: string): Promise<unknown> => import(name).catch(() => null);
const server = (await load("react-dom/server")) as { renderToString(node: ReactNode): string } | null;
const domClient = (await load("react-dom/client")) as { createRoot(container: unknown): { render(node: ReactNode): void; unmount(): void } } | null;
const skip = !server || !domClient ? "react-dom is not installed" : false;

type Bindings = typeof import("../src/flags/react.js");
type Req = { url: string; signal?: AbortSignal | null; body?: string };

/** Records requests; streams stay open (and can be pushed to) until aborted. */
function fakeFetch() {
  const requests: Req[] = [];
  const streams: { push(s: string): void; signal: AbortSignal | null | undefined }[] = [];
  const encoder = new TextEncoder();
  const f = (async (url: string, init: RequestInit = {}) => {
    requests.push({ url, signal: init.signal, body: init.body as string | undefined });
    if (url.includes("/events/")) return new Response(null, { status: 202 });
    if (url.includes("/flags?")) return Response.json({ f: { value: "from-fetch", variation: 0, version: 9 } });
    let push!: (s: string) => void;
    const body = new ReadableStream<Uint8Array>({ start: (c) => void (push = (s) => c.enqueue(encoder.encode(s))) });
    streams.push({ push: (s) => push(s), signal: init.signal });
    return new Response(body, { headers: { "content-type": "text/event-stream" } });
  }) as unknown as typeof fetch;
  return { f, requests, streams, of: (part: string) => requests.filter((r) => r.url.includes(part)) };
}

const flush = () => act(async () => void (await new Promise((r) => setTimeout(r, 15))));

describe("React bindings: server rendering", { skip }, () => {
  it("renders bootstrap values on the server without any request", async () => {
    const { DevPulseProvider, useFlag, useFlagsReady } = (await import("../src/flags/react.js")) as Bindings;
    const net = fakeFetch();
    const App = () => h("span", null, `${String(useFlag("new-checkout", false))}/${String(useFlagsReady())}`);
    const html = server!.renderToString(h(DevPulseProvider, { clientSideId: "cs", context: { key: "u1" }, options: { baseUrl: "https://flags.example.com", bootstrap: { "new-checkout": true }, fetch: net.f }, children: h(App) }));
    await new Promise((r) => setTimeout(r, 20));
    expect(html).toBe("<span>true/true</span>");
    expect(net.requests).toEqual([]);
  });
});

describe("React bindings: client", { skip }, () => {
  // ---- a minimal DOM ----
  class FakeNode {
    childNodes: FakeNode[] = [];
    parentNode: FakeNode | null = null;
    nodeValue: string | null = null;
    constructor(
      readonly nodeType: number,
      readonly nodeName: string,
      public ownerDocument: FakeDocument | null,
    ) {}
    get firstChild() {
      return this.childNodes[0] ?? null;
    }
    get lastChild() {
      return this.childNodes[this.childNodes.length - 1] ?? null;
    }
    get nextSibling(): FakeNode | null {
      const s = this.parentNode?.childNodes;
      return s ? (s[s.indexOf(this) + 1] ?? null) : null;
    }
    get tagName() {
      return this.nodeName;
    }
    get textContent(): string {
      return this.nodeType === 3 ? (this.nodeValue ?? "") : this.childNodes.map((c) => c.textContent).join("");
    }
    set textContent(v: string) {
      if (this.nodeType === 3) this.nodeValue = v;
      else {
        this.childNodes = [];
        if (v) this.appendChild(this.ownerDocument!.createTextNode(v));
      }
    }
    appendChild(c: FakeNode) {
      c.parentNode?.removeChild(c);
      this.childNodes.push(c);
      c.parentNode = this;
      return c;
    }
    insertBefore(c: FakeNode, ref: FakeNode | null) {
      if (!ref) return this.appendChild(c);
      c.parentNode?.removeChild(c);
      this.childNodes.splice(this.childNodes.indexOf(ref), 0, c);
      c.parentNode = this;
      return c;
    }
    removeChild(c: FakeNode) {
      this.childNodes.splice(this.childNodes.indexOf(c), 1);
      c.parentNode = null;
      return c;
    }
    addEventListener() {}
    removeEventListener() {}
    setAttribute() {}
    removeAttribute() {}
    style = {};
    namespaceURI = "http://www.w3.org/1999/xhtml";
  }
  class FakeDocument extends FakeNode {
    activeElement = null;
    body: FakeNode;
    documentElement: FakeNode;
    constructor() {
      super(9, "#document", null);
      this.body = this.createElement("body");
      this.documentElement = this.createElement("html");
    }
    createElement(tag: string) {
      return new FakeNode(1, tag.toUpperCase(), this);
    }
    createTextNode(text: string) {
      const n = new FakeNode(3, "#text", this);
      n.nodeValue = text;
      return n;
    }
  }

  async function setup() {
    const g = globalThis as Record<string, unknown>;
    const doc = new FakeDocument();
    g.window = { document: doc, HTMLIFrameElement: class {}, addEventListener() {}, removeEventListener() {}, event: undefined };
    g.document = doc;
    g.IS_REACT_ACT_ENVIRONMENT = true;
    // A fresh module instance, so it sees `window` (it checks once, at load).
    const bindings = (await import(`../src/flags/react.js?client=${Math.random()}`)) as Bindings;
    const container = doc.createElement("div");
    const root = domClient!.createRoot(container);
    return {
      bindings,
      container,
      render: (node: ReactNode) => act(async () => root.render(h(StrictMode, null, node))),
      unmount: () => act(async () => root.unmount()),
      teardown: () => {
        delete g.window;
        delete g.document;
      },
    };
  }

  it("StrictMode: ends up with one live client, no identify, and closes it on unmount", async () => {
    const env = await setup();
    try {
      const { DevPulseProvider, useFlag, useDevPulseClient } = env.bindings;
      const net = fakeFetch();
      const clients = new Set<unknown>();
      const App = () => {
        const c = useDevPulseClient();
        clients.add(c);
        return h("span", null, useFlag("f", "dflt"));
      };
      const tree = (key: string) => h(DevPulseProvider, { clientSideId: "cs", context: { key }, options: { baseUrl: "https://x", sendEvents: false, fetch: net.f }, children: h(App) });
      await env.render(tree("u1"));
      await flush();
      // StrictMode mounts, unmounts and remounts: the first client is closed, the second is live.
      const live = net.streams.filter((s) => !s.signal?.aborted);
      expect(live).toHaveLength(1);
      expect(net.of("/flags?")).toHaveLength(0); // no spurious identify
      live[0]!.push('event: put\ndata: {"f":{"value":"streamed","variation":1,"version":2}}\n\n');
      await flush();
      expect(env.container.textContent).toBe("streamed");
      const current = [...clients].pop() as { isClosed: boolean };
      expect(current.isClosed).toBe(false);

      // Same context again (new object): nothing happens.
      await env.render(tree("u1"));
      await flush();
      expect(net.of("/flags?")).toHaveLength(0);

      // A new context identifies the live client once.
      await env.render(tree("u2"));
      await flush();
      expect(net.of("/flags?")).toHaveLength(1);
      expect(env.container.textContent).toBe("from-fetch");

      await env.unmount();
      await flush();
      expect(current.isClosed).toBe(true);
      expect(net.streams.filter((s) => !s.signal?.aborted)).toHaveLength(0);
    } finally {
      env.teardown();
    }
  });

  it("re-renders on changes to flags named like Object.prototype members (constructor)", async () => {
    const env = await setup();
    try {
      const { DevPulseProvider, useFlag } = env.bindings;
      const net = fakeFetch();
      const App = () => h("span", null, useFlag("constructor", "dflt"));
      await env.render(h(DevPulseProvider, { clientSideId: "cs", context: { key: "u1" }, options: { baseUrl: "https://x", sendEvents: false, fetch: net.f }, children: h(App) }));
      await flush();
      const live = net.streams.filter((s) => !s.signal?.aborted)[0]!;
      live.push('event: put\ndata: {"constructor":{"value":"one","variation":0,"version":1}}\n\n');
      await flush();
      expect(env.container.textContent).toBe("one");
      live.push('event: patch\ndata: {"key":"constructor","value":"two","variation":1,"version":2}\n\n');
      await flush();
      expect(env.container.textContent).toBe("two");
      await env.unmount();
    } finally {
      env.teardown();
    }
  });

  it("first client render uses bootstrap without a request, then goes live", async () => {
    const env = await setup();
    try {
      const { DevPulseProvider, useFlag } = env.bindings;
      const net = fakeFetch();
      const seen: string[] = [];
      const App = () => {
        const v = useFlag("f", "dflt");
        seen.push(`${v}:${net.requests.length}`);
        return h("span", null, v);
      };
      await env.render(h(DevPulseProvider, { clientSideId: "cs", context: { key: "u1" }, options: { baseUrl: "https://x", sendEvents: false, bootstrap: { f: "boot" }, fetch: net.f }, children: h(App) }));
      expect(seen[0]).toBe("boot:0");
      expect(env.container.textContent).toBe("boot");
      await env.unmount();
    } finally {
      env.teardown();
    }
  });

  it("records each evaluation once (not per render) and keeps useTrack stable", async () => {
    const env = await setup();
    try {
      const { DevPulseProvider, useFlag, useTrack } = env.bindings;
      const net = fakeFetch();
      const tracks = new Set<unknown>();
      const App = (_: { tick: number }) => {
        tracks.add(useTrack());
        return h("span", null, useFlag("f", "dflt"));
      };
      // Re-rendering the tree (StrictMode renders twice each time) must not add evaluations.
      const Shell = ({ tick }: { tick: number }) =>
        h(DevPulseProvider, { clientSideId: "cs", context: { key: "u1" }, options: { baseUrl: "https://x", bootstrap: { f: "boot" }, flushIntervalMs: 1_000_000, fetch: net.f }, children: h(App, { tick }) });
      await env.render(h(Shell, { tick: 0 }));
      await flush();
      tracks.clear(); // the render-time placeholder client has been swapped for the live one
      await env.render(h(Shell, { tick: 1 }));
      await env.render(h(Shell, { tick: 2 }));
      await flush();
      await env.unmount(); // close() flushes events
      await flush();
      const events = net.of("/events/").flatMap((r) => JSON.parse(r.body!) as { kind: string; features?: Record<string, { counters: { count: number }[] }> }[]);
      const summary = events.find((e) => e.kind === "summary");
      expect(summary?.features?.f?.counters.reduce((n, c) => n + c.count, 0)).toBe(1);
      expect(tracks.size).toBe(1);
    } finally {
      env.teardown();
    }
  });
});
