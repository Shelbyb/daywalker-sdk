/**
 * Plays Daywalker's OAuth token endpoint in front of a test's mock fetch: POST /api/v1/oauth/token gets a
 * DPoP-bound token set, and every other request goes to `inner`, so call counts and header checks in the
 * wrapped mock only see the requests under test.
 */
export type TokenRequestLog = { grantType: string; authorization: string | null; dpop: string | null };

const b64url = (v: unknown) => Buffer.from(JSON.stringify(v)).toString("base64url");

export function fakeAccessToken(claims: Record<string, unknown> = {}): string {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    iss: "https://auth.daywalker.dev",
    sub: "0190c0de-0000-7000-8000-000000000001",
    user: { id: "0190c0de-0000-7000-8000-000000000001", name: "Test", email: "test@example.com" },
    services: ["svc"],
    iat: now,
    exp: now + 900,
    jti: Math.random().toString(36).slice(2),
    ...claims,
  };
  return `${b64url({ alg: "EdDSA", typ: "at+jwt" })}.${b64url(payload)}.c2ln`;
}

export function withOAuth(
  inner: (url: string | URL | Request, init?: RequestInit) => Promise<Response>,
  options: { services?: string[]; expiresIn?: number; log?: TokenRequestLog[]; tokenResponse?: () => Response | Promise<Response> } = {}
): typeof fetch {
  let n = 0;
  return (async (url: string | URL | Request, init?: RequestInit) => {
    const href = typeof url === "string" ? url : url instanceof URL ? url.href : url.url;
    if (new URL(href).pathname !== "/api/v1/oauth/token") return inner(url, init);
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? init.body : "";
    let grantType = "";
    try {
      grantType = String(JSON.parse(body).grant_type ?? "");
    } catch {
      grantType = new URLSearchParams(body).get("grant_type") ?? "";
    }
    options.log?.push({ grantType, authorization: headers.get("authorization"), dpop: headers.get("dpop") });
    if (options.tokenResponse) return options.tokenResponse();
    const services = options.services ?? ["svc"];
    const expiresIn = options.expiresIn ?? 900;
    n++;
    return Response.json({
      access_token: fakeAccessToken({ services, aud: services, exp: Math.floor(Date.now() / 1000) + expiresIn, n }),
      token_type: "DPoP",
      expires_in: expiresIn,
      expires_at: Math.floor(Date.now() / 1000) + expiresIn,
      refresh_token: `rt_${n}`,
      refresh_expires_in: 2_592_000,
      scope: services.join(" "),
      services,
    });
  }) as typeof fetch;
}
