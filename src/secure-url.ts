/** Dependency-free so every runtime entry point (browser, worker, edge) can use it. */
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);

/**
 * Throws unless `value` is an https: URL (http: is allowed only for localhost / 127.0.0.1 / [::1]),
 * so API keys, access tokens, SDK keys and write keys never travel in cleartext.
 */
export function assertSecureUrl(name: string, value: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    // The value isn't echoed: it may carry credentials or a key in its query string.
    throw new Error(`${name} must be an absolute https:// URL`);
  }
  if (url.username || url.password) {
    throw new Error(`${name} must not contain credentials`);
  }
  if (url.protocol === "https:") return;
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) return;
  throw new Error(`${name} must use https:// (http:// is only allowed for localhost); got "${url.protocol}//${url.host}"`);
}
