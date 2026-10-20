// Sign the POST /api/v1/oauth/token (client_credentials) request with RFC 9421 using signRequest.
import { signRequest } from "@shelbyb/daywalker-sdk";

export async function signedTokenRequest(authUrl: string, apiKey: string, signingKey: string, keyId: string) {
  const url = new URL("/api/v1/oauth/token", authUrl);
  const body = JSON.stringify({ grant_type: "client_credentials" });

  const signed = await signRequest({
    method: "POST",
    path: url.pathname,
    authority: url.host,
    body,
    key: signingKey,
    keyid: keyId,
  });

  const res = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${apiKey}`, ...signed } as Record<string, string>,
    body,
  });
  return res.json();
}
