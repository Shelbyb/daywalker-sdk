<p align="center">
  <img src="./assets/logo-512.png" alt="Daywalker" width="160" />
</p>

# @shelbyb/daywalker-sdk

Zero-dependency, runtime-agnostic client library for [Daywalker Auth](https://auth.daywalker.dev). Supports **RFC 9421 (HTTP Message Signatures)**, **RFC 9530 (Digest Fields)**, **Web Crypto standards**, **Push Architecture key registration**, and **hardened web & Next.js middleware**.

Runs seamlessly across **Node.js 18+**, **Bun**, **Deno**, **Cloudflare Workers**, **Next.js Edge**, and standard browser runtimes.

- **Zero-Dependency Web Standards Core**: 100% standard `crypto.subtle`, `Uint8Array`, `fetch`, `Request`, and `Response`.
- **RFC 9421 (HTTP Message Signatures)**: Cryptographically binds `@method`, `@path`, `@authority`, and `content-digest` using Ed25519 signatures (`Signature-Input`, `Signature`).
- **RFC 9530 (Digest Fields)**: Computes standard `Content-Digest: sha-256=:<base64>:` headers for payload integrity.
- **Class-Based Client Architecture**: Instantiable `Daywalker` client supporting dependency injection, with a lazy default singleton for plug-and-play simplicity.
- **Resilience & Rate Limiting**: Automatic exponential backoff with jitter and `Retry-After` header parsing directly inside client fetch requests.
- **Deterministic Type-Safe Results**: Discriminated union returns (`Result<T, E>`) for clean handling without try/catch boilerplate.
- **Security-Hardened Next.js Middleware**: Built-in Server Action probe mitigation (CVE-2025-55182 defense), health check bypass, and self-healing diagnostic error routing.
- **Zero-Egress Inbound Verification**: In-memory caching (60–300s TTL) and offline JWT token lease validation using Daywalker's asymmetric public key.
- **Decoupled Push Architecture CLI**: `npx daywalker init --json` registers keys directly via `POST /api/v1/keys/register` with zero runtime reverse-HTTP calls.

---

## Installation

```bash
npm install @shelbyb/daywalker-sdk
```

---

## Setup (once per service)

```bash
# Generate Ed25519 keypair and write .env.local
npx daywalker init --service my-service-slug

# Or register the public key immediately with Daywalker Auth (domain is required by the API):
npx daywalker init --service my-service-slug --domain app.example.com --api-key srv_live_...

# Pipe JSON secrets directly into Vercel, Fly.io, DigitalOcean, or AWS SSM:
npx daywalker init --service my-service-slug --api-key srv_live_... --json
```

`daywalker init`:
- Generates an Ed25519 keypair locally using WebCrypto (`crypto.subtle`)
- Registers the public JWK directly with `POST https://auth.daywalker.dev/api/v1/keys/register` (`Authorization: Bearer <API key>`, body `{ keyId, domain, publicKey }`; responds `201`)
- Writes `DAYWALKER_SERVICE_SLUG`, `DAYWALKER_KEY_ID`, `DAYWALKER_SIGNING_KEY`, and `DAYWALKER_AUTH_URL` to `.env.local`
- No route injectors or public `/.well-known/` endpoints needed

The private key is never printed unless you pass `--print-key`.

---

## Environment

| Variable | Required | Purpose |
|---|---|---|
| `DAYWALKER_API_KEY` | ✅ | The service's Daywalker API token (`srv_live_…`) or JWT lease |
| `DAYWALKER_SERVICE_SLUG` | ✅ | The service slug to validate against (e.g. `sonalyze`) |
| `DAYWALKER_SIGNING_KEY` | for signed requests | Ed25519 private key from `daywalker init` (PKCS#8 Base64 DER or PEM) |
| `DAYWALKER_KEY_ID` | optional | RFC 7638 JWK thumbprint derived during key generation |
| `DAYWALKER_SIGNING_KEY_PREVIOUS` | during rotation | Previous private key, maintained during deployment transitions |
| `DAYWALKER_DOMAIN` | optional | Optional caller identifier or host domain name |
| `DAYWALKER_PUBLIC_KEY` | optional | Daywalker Auth public key for zero-egress offline JWT lease verification |
| `DAYWALKER_AUTH_URL` | optional | Defaults to `https://auth.daywalker.dev` |

---

## Usage

### Client Class & Instantiation

```ts
import { Daywalker, daywalker } from "@shelbyb/daywalker-sdk";

// Option 1: Instantiable client with custom options / dependency injection
const client = new Daywalker({
  apiKey: process.env.DAYWALKER_API_KEY,
  serviceSlug: "sonalyze",
  maxRetries: 3,
});

// Option 2: Default lazy singleton (reads process.env automatically)
const result = await daywalker.validateToken();

if (result.ok) {
  console.log("Validated tenant:", result.data.tenantId);
  console.log("Rate limit remaining:", result.data.rateLimit.remaining);
} else {
  console.error(`Validation failed (${result.status} ${result.error}): ${result.message}`);
}
```

### Type-Safe Verification & Error Handling

```ts
// requireValidToken returns data or throws DaywalkerAuthError / DaywalkerRateLimitError
try {
  const auth = await client.requireValidToken(req.headers.get("x-api-token"));
  console.log("Authenticated service:", auth.serviceSlug);
} catch (err) {
  if (err instanceof DaywalkerRateLimitError) {
    console.warn(`Rate limited. Retry after ${err.retryAfter}s`);
  }
}
```

### RFC 9421 Signed Requests with Automatic Backoff

```ts
// Outbound request automatically computes Content-Digest (RFC 9530)
// and attaches RFC 9421 signature headers. Retries 429 rate limits automatically.
const res = await client.fetch("/api/v1/tokens/validate", {
  method: "POST",
  body: { token: "user_token", serviceSlug: "other-service" },
});
```

---

## Hardened Next.js Middleware (`@shelbyb/daywalker-sdk/next`)

```ts
// middleware.ts
import { createDaywalkerMiddleware } from "@shelbyb/daywalker-sdk/next";

export const middleware = createDaywalkerMiddleware({
  serviceSlug: "sonalyze",
  errorPath: "/service-error", // redirect unauthorized web visitors
  validateServerActions: true, // drops malformed CVE-2025-55182 scanner probes
});

export const config = {
  matcher: ["/((?!_next/static|_next/image|favicon.ico).*)"],
};
```

### Route Handler Wrapper

```ts
// app/api/protected/route.ts
import { withDaywalkerAuth } from "@shelbyb/daywalker-sdk/next";

export const POST = withDaywalkerAuth(async (req, { auth }) => {
  return Response.json({ message: "Hello " + auth.serviceSlug, auth });
});
```

---

## Web Standard & Hono Middleware (`@shelbyb/daywalker-sdk/middleware`)

```ts
import { Hono } from "hono";
import { daywalkerAuth } from "@shelbyb/daywalker-sdk/middleware";

const app = new Hono();
app.use("/api/*", daywalkerAuth());

app.get("/api/me", (c) => {
  const auth = c.get("auth");
  return c.json({ auth });
});
```

---

## Zero-Egress Offline Verification

When high-throughput internal microservices need zero latency and zero external egress, Daywalker Auth can issue asymmetric JWT leases. Configure `DAYWALKER_PUBLIC_KEY` (PEM or standard JWK) and token validation runs entirely in memory without network calls:

```ts
import { Daywalker } from "@shelbyb/daywalker-sdk";

const client = new Daywalker({
  serviceSlug: "myservice",
  daywalkerPublicKey: process.env.DAYWALKER_PUBLIC_KEY,
});

// Verifies JWT signature, expiration, and service claims locally
const result = await client.validateToken(incomingJwt);
```

---

## CLI Reference

| Command | Description |
|---|---|
| `npx daywalker init --service <slug> [--api-key <key>] [--json]` | Generate Ed25519 key, register with Daywalker Auth, and write `.env.local` or output JSON |
| `npx daywalker check` | Validate configuration, signature readiness, and connection |
| `npx daywalker rotate [--api-key <key>] [--json]` | Generate and register a new key while preserving the previous key in `.env.local` |

---

## API Reference (per the [OpenAPI spec](https://auth.daywalker.dev/docs))

| Endpoint | SDK usage | Notes |
|---|---|---|
| `POST /api/v1/tokens/validate` | `client.validateToken()` | Body `{ token, serviceSlug }`; signed with `Signature-Input`, `Signature`, `Content-Digest`. Errors: `400` (`DIGEST_MISMATCH`/missing fields), `401` (`INVALID_SIGNATURE`/invalid token), `403`, `429`. Response includes `valid`, `tokenId`, `tokenName`, `userId`, `stage`, `rateLimit`, `rateLimitHourly` and `X-RateLimit-*` / `X-RateLimit-Hourly-*` headers |
| `POST /api/v1/keys/register` | `npx daywalker init` / `rotate` | Bearer auth; body `{ keyId, domain, publicKey }` |
| `POST /api/v1/leases/issue` | `client.issueLease(ttlSeconds?)` | Signed request returns `{ lease, tokenType, expiresAt, jwksUri }` (EdDSA JWT) |
| `GET /.well-known/jwks.json` | `client.fetchJwks()` | Daywalker public JWKS for offline lease verification |

Inbound tokens may be supplied as `x-api-token: srv_live_...` or `Authorization: Bearer <JWT or API key>`.

---

## Request Signing Specification (RFC 9421 & RFC 9530)

Each outbound request signed by `@shelbyb/daywalker-sdk` includes:
- `Content-Digest: sha-256=:<base64-encoded-hash>:`
- `Signature-Input: sig1=("@method" "@path" "@authority" "content-digest");created=<unix_seconds>;keyid="<kid>";alg="ed25519";nonce="<random>"`
- `Signature: sig1=:<base64-encoded-signature>:`
- `Authorization: Bearer <DAYWALKER_API_KEY>`

A fresh random `nonce` is generated for every attempt (including retries), so identical requests in the same second still produce unique signatures and never trip replay protection. `validateToken()` also shares one in-flight request between concurrent callers for the same token, and briefly caches failures (`negativeCacheTtlMs`, default 3000ms; 429s and network errors are never cached).

The exact signature base and test cases are verified against [`test-vectors/signing-rfc9421.json`](./test-vectors/signing-rfc9421.json).

---

## License

MIT
