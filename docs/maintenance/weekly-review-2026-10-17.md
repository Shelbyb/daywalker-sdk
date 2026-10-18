# Weekly review — 2026-10-17

**Summary**
- No vulnerabilities: `npm audit` and `npm audit --omit=dev` both report 0 advisories. Tests (236/236), typecheck, publint and attw all pass. The packed tarball (74 files, 95.5 kB packed / 326.9 kB unpacked) matches the published 0.4.1.
- The code changed this week (the 0.4.0 hardening: signing, JWT leases, middleware, flags, RE2-based `matches`) reads as sound. I found nothing High.
- Main decisions for you: **Node 20 is EOL** (since 2026-04-30) but `engines` still allows it, and **re2js 2.8.7 and 2.8.8 both came out today**. I left re2js pinned at 2.8.6 for now; see Dependencies.
- Safe fixes on branch `maintenance/weekly-2026-10-17`: corrected the inaccurate "zero-dependency" description, kept `docs/maintenance/` out of the npm tarball, and updated the `@types/node` lockfile entry (26.6.4 → 26.6.5).

This is the first weekly report, so this review covers everything from `git log --since="8 days ago"` (0.4.0 and 0.4.1).

## Security

- **Low: JWT and signature error messages echo attacker-controlled values.** `verifyJwtLease` puts `alg`, `typ`, `aud` and `iss` into its error strings, and `verifyRequestSignature` does the same with the received `Content-Digest` (`src/crypto/signatures.ts`). If callers log `error` verbatim, an attacker can inject arbitrary text (including newlines) into those logs. *Action:* truncate the echoed values and strip control characters, or return a fixed error code with the details in a separate field.
- **Low: `registerPublicKey` has no timeout.** The CLI key-registration `fetch` (`src/crypto/signatures.ts`) doesn't use the client's `timeoutMs`, so a server that never responds can hang `daywalker init`/`rotate`. *Action:* pass an `AbortSignal.timeout(...)`.
- **Low: the cached flag set isn't checked for shape.** `readCache()` in `src/flags/client.ts` trusts whatever JSON is in `localStorage`. It is wrapped with a prototype-free `flagMap`, so there is no prototype pollution, but malformed entries reach evaluation. *Action:* run it through `isFlagSet` and drop it if that fails.
- **Info (no action): crypto reviewed and OK.** Comparisons are constant-time (`timingSafeEqual`). Signatures require canonical base64, cover `@method`/`@path`/`@authority`, and require `@query` and `content-digest` coverage when the request has a query or body. Clock skew is bounded, the replay cache fails closed, and `alg` is allow-listed. JWTs reject `crit` and require `exp` and an audience. RE2 removes the `matches` ReDoS risk, and pattern and input lengths are capped. The CLI runs output through `redactSecrets` and warns about `--api-key` and `--json` exposing secrets.
- **Low: workflow hygiene is good, with one small gap.** Every action is pinned to a SHA, top-level `permissions: contents: read` is set, `id-token: write` is granted only to the publish job, the build job runs `npm ci --ignore-scripts`, the publish job uploads only the packed tarball, and provenance is on. The gap: `actions/checkout` keeps its default `persist-credentials: true`. *Action:* add `persist-credentials: false` to both checkouts. Optionally, run CI's `npm ci` with `--ignore-scripts` too.
- **Low: npm's "allow-scripts" warning.** While I ran `npm update`, npm reported install scripts waiting for approval and did not run them. Nothing failed. *Action:* run `npm approve-scripts --allow-scripts-pending` locally once to see which package it is.

## Dependencies

`npm outdated`:

| Package | Current | Wanted | Latest | Notes |
|---|---|---|---|---|
| `@types/node` (dev) | 26.6.4 | 26.6.5 | 26.6.5 | Patch. **Updated on the branch.** |
| `re2js` (runtime, exact pin) | 2.8.6 | 2.8.6 | 2.8.8 | Patch. **Not updated**, see below. |

- **Medium: re2js 2.8.7 and 2.8.8 were both published today (2026-10-17).** Same maintainer, with npm provenance and no install scripts. The diff is a reformatted README and about 1.5k changed lines in the built bundles. Since re2js is the only runtime dependency, and so ships to every user, I didn't adopt two releases from the same day before they've had time to settle. *Action:* next week, read the upstream changelog and the `build/index.js` diff, then bump the exact pin. Separately, decide whether to keep the exact pin (you control every byte, but users only get re2js fixes through an SDK release) or switch to `~2.8.6`.
- **Medium: Node 20 reached end of life on 2026-04-30.** `engines` is `>=20.19`, the README says "Node.js 20.19+", and CI tests 20/22/24. *Action:* in the next minor (pre-1.0) or major release, raise `engines` to `>=22.12`, drop 20 from CI and the README, and add Node 26 to the CI matrix. This is breaking for anyone still on 20, so it needs a CHANGELOG entry.
- **Low: `@types/node` is on major 26, but the package supports Node 20 and later.** Typecheck won't flag a Node 22+ or 26 API used in `src/`. *Action:* pin `@types/node` to the lowest supported major (`^22` once 20 is dropped) and tell Dependabot to ignore its major updates.
- **Low: peer ranges are much older than what CI tests.** The peers are `@openfeature/server-sdk ^1.17.0`, `@openfeature/web-sdk ^1.5.0` and `react >=18`, but CI only installs the latest releases (1.23.0, 1.10.0 and React 19.3). Both current OpenFeature SDKs now require `@openfeature/core ^1.12.0`. *Action:* either add a CI job that installs the minimum peer versions (and React 18), or raise the floors to versions that are tested.
- **Low: the publish job pins `npm@11.6.2`, and npm 12.2.0 is now out.** 11.6.2 is still fine for trusted publishing. *Action:* when convenient, evaluate npm 12 and move the pin.

## Package improvements

- **Medium (fixed on the branch): the `description` said "zero-dependency".** That stopped being true in 0.4.0, when `re2js` was added. It now reads "…in one package with a single runtime dependency (re2js)."
- **Medium (fixed on the branch): `files` includes `docs`, so reports in `docs/maintenance/` would ship to npm.** I added `"!docs/maintenance"` to `files`. `npm pack --dry-run` confirms the tarball contents haven't changed.
- **Low: CHANGELOG.** I added an `Unreleased` section with the metadata fixes above, so the next release picks them up.
- **Low: README.** The README never says the package has one runtime dependency (only the CHANGELOG does). *Action:* add one line under the runtime-support line, so users who review dependencies aren't surprised.
- **Info (no action): exports, types and tree-shaking are OK.** All 11 subpaths resolve with types under node16-ESM and bundler (attw `esm-only` profile), `sideEffects: false` is set, and there are no source maps or tests in the tarball.
