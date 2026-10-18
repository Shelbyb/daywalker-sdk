/**
 * WebCrypto primitives captured once, when this module loads. Every signature, digest and key operation in
 * the SDK goes through these, so code that later replaces `crypto.subtle.verify` (or `crypto.subtle`
 * itself) can't make forged signatures or tokens verify. The object is frozen so the captured functions
 * can't be swapped either. Without WebCrypto each call throws (fail closed) instead of the import failing.
 */
const cryptoRef: Crypto | undefined = globalThis.crypto;
const subtleRef: SubtleCrypto | undefined = cryptoRef?.subtle;

function missing(): never {
  throw new Error("@shelbyb/daywalker-sdk needs WebCrypto (globalThis.crypto.subtle): Node.js 20.19+, Bun, Deno, Workers or a browser");
}

function capture<T extends object, K extends keyof T>(target: T | undefined, name: K): T[K] {
  const fn = target?.[name];
  return (typeof fn === "function" ? fn.bind(target) : missing) as T[K];
}

export const webcrypto = Object.freeze({
  digest: capture(subtleRef, "digest"),
  sign: capture(subtleRef, "sign"),
  verify: capture(subtleRef, "verify"),
  importKey: capture(subtleRef, "importKey"),
  exportKey: capture(subtleRef, "exportKey"),
  generateKey: capture(subtleRef, "generateKey"),
  getRandomValues: capture(cryptoRef, "getRandomValues"),
  randomUUID: capture(cryptoRef, "randomUUID"),
});
