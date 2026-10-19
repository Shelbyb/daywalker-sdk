# `daywalker license`: apply and check the DevPulse source-available license

For projects that ship under the **DevPulse Source-Available License** (the text is `src/license/templates.ts`; it is
installed as `LICENSE`). The license requires `@shelbyb/daywalker-sdk` for license verification, metering and rate
limiting, and forbids removing or bypassing it. This command puts the license in place and keeps it there.

```sh
npx -p @shelbyb/daywalker-sdk daywalker license apply --governing-law "the State of …"
npx -p @shelbyb/daywalker-sdk daywalker license check     # exits 1 when anything is missing: use it in CI
```

## What `apply` does (idempotent; `--dry-run` shows the plan)

| Step | Details |
|---|---|
| `LICENSE` | Writes the current text. A *different* existing license is kept unless you pass `--replace-existing` (people who already received copies keep the old terms). A governing-law clause you filled in earlier is preserved. |
| `package.json` | `"license": "SEE LICENSE IN LICENSE"` in the root and every workspace package, inserted as text so formatting is untouched. **`"private"` is never changed**, and a package that already declares another license (say MIT) is left alone and listed (use `--replace-existing` to change it). |
| `README.md` | Adds or replaces a `## License` section after the first prose paragraph. |
| Notice headers | A block comment on every source file that imports `@shelbyb/daywalker-sdk` (static, dynamic or `require`) or calls a guard (`validateServiceCredentials`, `validateToken`, `getLicense`, `fetchBundle`, or your own via `--guard-names a,b`; add files with `--include a.ts,b.ts`, skip files with `--exclude 'src/ui/**,scripts/*.mjs'`). Tests, `.d.ts`, `docs/`, `examples/` and `node_modules` are skipped. Shebangs stay first. Comments only: **it never edits code that calls the SDK**. |
| Boot log line | Added to `register()` in a Next.js `instrumentation.ts` (found in the root, `src/` or a workspace). Otherwise listed as a to-do with the exact line. |
| Build output and Docker | Listed as to-dos: keep the header as a bundler banner (tsup/esbuild `banner.js`, Vite/Rollup `output.banner`, Webpack `BannerPlugin({ raw: true })`) and copy `LICENSE` to the output directory and into the image. |

`check` verifies the LICENSE text, the package fields, the README section, every header and the boot line.

## Notes from the license review

The text was redrafted from the first version (which mixed MIT's "without restriction ... sublicense" with "All rights
reserved") to follow the structure of Elastic License 2.0, PolyForm and FSL/BSL: defined terms, a non-sublicensable
grant, a no-circumvention clause (with examples), a Free Tier/Commercial Tier split, redistribution conditions, patent,
trademark, termination with a 30-day cure, and standard warranty and liability terms. It is **source-available, not
open source**. It is not legal advice; have counsel review it. Open decisions for the owner:

1. Governing law and venue (a placeholder until you pass `--governing-law`).
2. Whether the Free Tier limits should also be published on a versioned limits page the license points to.
3. A written agreement or terms of service for the Commercial Tier.
4. A privacy notice for the usage data metering sends.
5. The SDK's own license terms (this package is published under its own proprietary terms).
6. Whether to forbid third parties from offering the software as a hosted service.
7. Optionally, a change date after which old versions become open source.
8. Whether the rights are held by the LLC, the individual, or both.
