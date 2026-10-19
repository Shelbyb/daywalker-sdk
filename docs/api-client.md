# Management API client

`@shelbyb/daywalker-sdk/api` is a small typed client for DevPulse's REST API (`/api/v1`) built only on `fetch`. It runs in Node 20+, Deno, Bun and Cloudflare Workers. **Never ship the client secret to a browser**; use it from servers, CI and workers.

```ts
import { createApiClient, ApiProblemError } from "@shelbyb/daywalker-sdk/api";

const api = createApiClient({
  host: "https://devpulse.example.com",
  clientId: process.env.DEVPULSE_CLIENT_ID!,
  clientSecret: process.env.DEVPULSE_CLIENT_SECRET!,
  scope: "flags:read flags:write", // optional
});

const { data, etag } = await api.get<{ key: string }>("/api/v1/projects/web/flags/new-checkout");
await api.patch("/api/v1/projects/web/flags/new-checkout", { description: "x" }, { ifMatch: etag! });

for await (const project of api.paginate<{ key: string }>("/api/v1/projects", { query: { limit: 100 } })) console.log(project.key);

try {
  await api.post("/api/v1/projects", { name: "" });
} catch (err) {
  if (err instanceof ApiProblemError) console.error(err.status, err.title, err.detail, err.errors, err.problem.requiredPlan);
}
```

* **Auth**: OAuth 2.0 client credentials (RFC 6749 4.4) at `{host}/oauth/token` with HTTP Basic; the token is cached and refreshed `refreshSkewSeconds` (60) before it expires, concurrent callers share one request, and a `401` refreshes once. Secrets travel only in headers and bodies, never in a URL, and `toJSON()` hides them. Token failures throw `ApiAuthError` (`code` is the RFC 6749 error, or `network_error`).
* **Errors**: non-2xx responses throw `ApiProblemError` (RFC 9457): `status`, `type`, `title`, `detail`, `errors[]`, `problem` (including extension members such as `requiredPlan`), `retryAfter`, `headers`, `isRateLimited`, `isPreconditionFailed` (412).
* **Pagination**: `api.paginate(path)` yields items, `api.pages(path)` yields responses; both follow `Link: <...>; rel="next"` (RFC 8288). A link to another origin is never followed, so the bearer token cannot leak.
* **Retries**: `429` always, `503` for requests that are safe to repeat (not `POST`/`PATCH`), up to `maxRetries` (3), honoring `Retry-After` (seconds or date, capped by `maxRetryDelayMs`, 30 s), otherwise exponential backoff with jitter from `retryBaseMs` (500).
* **Conditional writes**: `ifMatch` sends `If-Match`; responses expose `etag`. `res.rateLimit` parses the IETF `RateLimit` / `RateLimit-Policy` headers.
* **Safety**: `host` must be HTTPS (or localhost), paths must be relative to the host, redirects are an error, each attempt has a timeout (`timeoutMs`, 30 s) and accepts an `AbortSignal`.

Responses are `{ status, data, headers, etag, rateLimit, next }`.
