# DevPulse SDK wire protocol

A language-neutral contract for writing a DevPulse SDK (Python, Go, Ruby, ...). Everything here is what the JavaScript SDK in this repository does; the JSON files in [`test-vectors/`](../test-vectors) let another implementation prove it agrees. All requests are HTTPS (plain `http://` only for `localhost`, `127.0.0.1` and `[::1]`). **Never put a key in a URL** except where this document says so (the client-side ID, which is public, and the secure-mode `h` hash).

Base URL: your DevPulse origin, e.g. `https://devpulse.example.com` (no trailing slash). Send a `User-Agent` such as `DevPulsePython/1.2.3`.

## Credentials

| Credential | Where it comes from | Used for | Sent as |
| --- | --- | --- | --- |
| Server SDK key | Project, Environments & keys | server flags, server events | `Authorization: <key>` (a `Bearer ` prefix is also accepted) |
| Mobile key | same | mobile flags, events | same |
| Client-side ID | same (public) | browser flags, client events | in the URL path |
| Analytics write key `dpa_...` | Analytics, Settings (public) | `/a/batch`, `/a/rum` | `api_key` / `key` in the JSON body |
| API client id and secret | Settings, API clients | management REST API | HTTP Basic on `/oauth/token`, then `Authorization: Bearer <token>` |

## 1. Client-side evaluation (the server evaluates; the simplest SDK)

`GET /sdk/v1/client/{clientSideId}/flags?context=<base64url JSON>` or `POST /sdk/v1/client/{clientSideId}/flags` with the context as the JSON body (max 32 KB).

Query parameters: `h` (secure-mode hash, below), `withReasons=true`.

Response `200`:

```json
{ "new-checkout": { "value": true, "variation": 1, "version": 7 },
  "banner": { "value": "spring", "variation": 0, "version": 3, "reason": { "kind": "FALLTHROUGH" } } }
```

`variation` is the index (or `null`), `version` the flag version. `reason` appears with `withReasons=true` or for experiments (then `trackReason: true`); `trackEvents: true` means the SDK should send a full `feature` event. Only flags marked available to client-side SDKs are returned. `ETag` / `If-None-Match` give `304`. Errors: `400` invalid context, `403` secure mode without a valid hash, `404` unknown client-side ID. Responses are JSON `{ "error": "..." }`.

**Context encoding in a URL**: `base64url(JSON.stringify(context))` with the URL-safe alphabet (`-` `_`) and **no `=` padding**.

**Secure mode**: when enabled for the environment send `h=<hex>` where `hex = lowercase HMAC-SHA256(key = server SDK key (UTF-8), message = canonicalKey (UTF-8))`. See `test-vectors/secure-mode-hash.json`. Compute it on your server, never in the browser.

**Streaming**: `GET /sdk/v1/client/{clientSideId}/stream?context=...&h=...` is `text/event-stream` (WHATWG SSE). Events: `put` (data: the full flag map above), `patch` (data: `{ "key": "...", "value": ..., "variation": n, "version": n }`, apply only when the version is not older than the held one), `delete` (data: `{ "key": "...", "version": n }`, apply when `version >= held`). Heartbeat comments keep the connection open. Reconnect with exponential backoff (1 s doubling to 30 s), honor a server `retry:` hint (at least 1 s), reconnect if nothing arrives for 5 minutes, keep serving the last data while disconnected, and stop on `401`/`403`/`404`. In browsers send only CORS-safelisted headers.

## 2. Server ruleset and local evaluation

`GET /sdk/v1/server/flags` with `Authorization: <server SDK key>`. Send `If-None-Match: <etag>` on later polls; `304` means unchanged. Poll no more often than every 30 s. `401`/`403`: invalid key (stop). Response:

```json
{ "flags": { "<key>": { "key": "...", "version": 3, "on": true, "salt": "...", "variations": [false, true],
                          "offVariation": 0, "fallthrough": { "variation": 0 }, "targets": [], "rules": [], "prerequisites": [] } },
  "segments": { "<key>": { "key": "...", "version": 1, "salt": "...", "included": [], "excluded": [], "rules": [] } } }
```

Streaming: `GET /sdk/v1/server/stream` (same auth). Events: `put` with `{ "path": "/", "data": <the ruleset above> }` (replace everything), `patch` with `{ "path": "/flags/<key>" | "/segments/<key>", "data": <item> }` (upsert only if the item's `version` is greater than the held one), `delete` with `{ "path": "...", "version": n }` (delete if the held version is lower than `version`). Treat a flag with `"deleted": true` as absent.

### Data model

Flag: `key`, `version`, `on`, `salt`, `variations[]` (any JSON), `offVariation` (index or null), `fallthrough` and each `rule` are a *variation or rollout*, `targets[] {contextKind?, values[], variation}`, `rules[] {id, clauses[], variation | rollout}`, `prerequisites[] {key, variation}`. Clause: `{contextKind?, attribute, op, values[], negate?}`. Rollout: `{kind?: "rollout"|"experiment", contextKind?, bucketBy?, seed?, variations[] {variation, weight, untracked?}}`, weights in 0..100000 (thousandths of a percent). Segment: `included[]` / `excluded[]` (`{contextKind?, values[]}`), `rules[] {id, clauses[], weight?, rolloutContextKind?, bucketBy?}`.

### Contexts

A context is `{ "kind": "user", "key": "u1", ...attributes }` (a missing `kind` means `"user"`) or `{ "kind": "multi", "user": {"key": "u1"}, "org": {"key": "acme"} }`. A kind matches `^[a-zA-Z0-9._-]+$` and is not `"kind"` or `"multi"`; every context needs a non-empty **string** `key`; `anonymous: true` is a flag; `_meta.privateAttributes` lists attributes never sent to DevPulse. Anything else invalid means evaluation returns the default with reason `ERROR`/`USER_NOT_SPECIFIED`.

`canonicalKey` is the key for a single `user` context; otherwise the contexts sorted by kind (ordinal string compare), each rendered `kind:key` with `%` -> `%25` then `:` -> `%3A` in the key, joined with `:`. See `test-vectors/flags-context.json`.

**Prototype safety**: attribute lookups must only read attributes the context itself defines (`constructor`, `__proto__`, `toString` must resolve to nothing unless set). Attribute references starting with `/` are RFC 6901 JSON Pointers (`~1` -> `/`, `~0` -> `~`), where array indexes must be canonical non-negative integers; other references are literal names. `key` and `kind` are always available.

### Evaluation order

1. flag `on == false`: serve `offVariation` (value `null`, index `null` when it is null). Reason `OFF`.
2. Prerequisites in order: each prerequisite flag must exist, not be deleted, be `on`, and evaluate to variation `prerequisite.variation` (evaluated recursively; a cycle is `MALFORMED_FLAG`). On failure serve the off variation with reason `PREREQUISITE_FAILED` (`prerequisiteKey`).
3. Targets in order: first target whose `contextKind` (default `user`) is in the context and whose `values` contain that context's `key`: reason `TARGET_MATCH`.
4. Rules in order: a rule matches when **every** clause matches. Serve it: reason `RULE_MATCH` (`ruleIndex`, `ruleId`).
5. `fallthrough`: reason `FALLTHROUGH`.

"Serve" a variation-or-rollout: a `variation` index, or the rollout (below). An index outside the variations array, a rule with neither, or an empty rollout is `MALFORMED_FLAG`. An `ERROR` or a `null` result returns the caller's default value with the reason. Reasons for experiments add `inExperiment: true` when the rollout `kind` is `experiment`, the context kind was found and the picked variation is not `untracked`.

**Clause matching** (`contextKind` default `user`): the context must have that kind, otherwise the clause is false **even when negated**. Operator `segmentMatch`: true if any value is the key of a segment the context is in (depth limit 10, then `MALFORMED_FLAG`); `negate` inverts. Attribute `kind` matches against every kind present. Otherwise read the attribute; `undefined`/`null` never matches (also when negated). An array attribute matches if any element matches; a clause matches if any element matches any clause value; then `negate` inverts the result. Operators: see `test-vectors/flags-operators.json` (`in`, `startsWith`, `endsWith`, `contains`, `matches`, `lessThan`, `lessThanOrEqual`, `greaterThan`, `greaterThanOrEqual`, `before`, `after`, `semVerEqual`, `semVerLessThan`, `semVerGreaterThan`). `matches` is RE2 (Go's `regexp` is the same engine; Python and Ruby need an RE2 binding or a safe subset, because backtracking engines allow ReDoS and accept lookaround that must instead never match).

**Segment match**: `included` containing the context's key (for that `contextKind`): match; else `excluded`: no match; else the first rule whose clauses all match decides: with no `weight` it matches, with a `weight` it matches when `bucket(segment.key, segment.salt, rolloutContextKind, bucketBy) < weight/100000`. Otherwise no match. Deleted or unknown segments never match.

### Bucketing

For rollouts, `bucketBy` defaults to `key` and `contextKind` to `user`. If the context lacks the kind, bucket is `0` and the experiment is not tracked. The bucketed attribute must be a string, or an integer (rendered in base 10); anything else buckets to `0`. Then:

```
input  = seed set ? "<seed>.<id>" : "<flagKey>.<salt>.<id>"      (segments use "<segmentKey>.<salt>.<id>")
bucket = float64(int(first 15 hex digits of sha1(input), 16)) / float64(0xFFFFFFFFFFFFFFF)     in [0, 1]
```

The input is UTF-8. The integer is up to 60 bits; use 64-bit integers or arbitrary precision and one final float64 division, comparing with a tolerance of 1e-12 in tests (`test-vectors/flags-bucketing.json`). Walk the weighted variations summing `weight/100000`; the first whose running sum exceeds `bucket` wins; if none does, use the last. Full end-to-end cases live in `test-vectors/flags-eval.json` (`evaluateFlag(store(flags, segments), flag, context, default)` must equal `expect` exactly).

## 3. Event endpoints

Send flag analytics so DevPulse can show evaluation counts, context lists and experiments. Bodies are JSON **arrays** of events, max 5000 events and about 500 KB per request (split larger batches); beacons and `keepalive` bodies must stay under 64 KB.

* Server: `POST /sdk/v1/events` with `Authorization: <server SDK key>`. Mobile keys are accepted too. `202` with `X-Events-Accepted`; `401` invalid key; `429` with `Retry-After` (2000 requests a minute per environment); `400` bad body. Do not retry other `4xx`; retry `5xx`/`429` once after a second. On `401`/`403` stop sending (the key is wrong).
* Client: `POST /sdk/v1/events/client/{clientSideId}`, no auth header, CORS enabled (use `text/plain`/`sendBeacon` from browsers).

Event kinds (extra kinds are ignored): `summary` `{startDate, endDate, features: {<flagKey>: {default, counters: [{variation, version, value, count} | {value, count, unknown: true}]}}}`; `index` and `identify` `{creationDate, context}`; `feature` `{creationDate, key, version, variation, value, default, contextKeys, reason?}` (only for flags with `trackEvents`, or experiments); `custom` `{key, creationDate, contextKeys: {<kind>: <key>}, data?, metricValue?}`. Remove private attributes from `context` and list their names in `redactedAttributes`. Send an `index` event the first time a context is seen in 5 minutes.

## 4. Product analytics

`POST /a/batch`, `Content-Type: application/json` (or `text/plain` from `sendBeacon`):

```json
{ "api_key": "dpa_...", "sent_at": "2026-01-01T00:00:00.000Z",
  "batch": [ { "uuid": "<uuid v7>", "event": "signed_up", "distinct_id": "user-1", "timestamp": "2026-01-01T00:00:00.000Z",
               "properties": { "plan": "pro", "$lib": "devpulse-python", "$lib_version": "1.0.0" },
               "$set": { "email": "a@b.c" }, "$set_once": {} } ] }
```

At most 100 events and about 1 MB per request; `4xx` (except `429`) means drop the batch, `5xx`/`429`/network errors mean requeue and back off (1 s doubling to 60 s). Identify a user with an `$identify` event (`properties.$anon_distinct_id` is the previous anonymous id); `$pageview` for page views; `$set` events for person properties. Server SDKs pass `distinct_id` per call and send no `$session_id`.

## 5. Web Vitals

`POST /a/rum`; see [analytics.md](./analytics.md) for the payload.

## 6. Management REST API

See [api-client.md](./api-client.md): OAuth 2.0 client credentials at `/oauth/token`, Bearer tokens, RFC 9457 problems, RFC 8288 `Link` pagination, IETF `RateLimit` headers, `429`/`503` with `Retry-After`, `ETag`/`If-Match` (`412`).

## Conformance checklist

1. Run the four `test-vectors/*.json` files (`flags-eval`, `flags-bucketing`, `flags-context`, `flags-operators`) plus `secure-mode-hash`.
2. Never send a key in a URL (except client-side IDs and `h`), never follow a redirect with credentials, HTTPS-only.
3. Treat attribute maps as prototype-free; never read inherited properties.
4. Cap queues, back off on failures, and stop sending on `401`/`403`.
