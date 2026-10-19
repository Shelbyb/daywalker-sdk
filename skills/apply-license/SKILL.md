---
name: apply-license
description: Apply or verify the DevPulse source-available license (LICENSE, package.json license fields, README section, notice headers on SDK files, boot log line, bundler banner, Docker copy) in any project that uses @shelbyb/daywalker-sdk. Use when the user asks to add, update or check the license, licensing headers or license notices in a project.
---

# Apply the DevPulse source-available license

The license requires `@shelbyb/daywalker-sdk` and forbids removing or bypassing it. The SDK ships a command that does
the mechanical parts safely and repeatably; you handle the project-specific parts and verify.

## Never
- Edit, move, wrap, stub or "tidy" any SDK import or guard call. Headers are comments only.
- Change `"private"` in a package.json unless the user said so for that package (a monorepo root with `private: false` can be published by accident).
- Replace an existing different LICENSE without asking: earlier recipients keep the old terms.
- Invent the governing law: it is the owner's decision (ideally with counsel).
- Apply this license to the `daywalker-sdk` repository itself (it has its own terms).
- Commit or push; leave the diff for the user.

## Steps
1. Find the project root and check it uses the SDK (`grep -r "@shelbyb/daywalker-sdk" --include=package.json .`). If not, stop and ask.
2. Preview: `npx -p @shelbyb/daywalker-sdk@latest daywalker license apply --dry-run` (add `--dir <path>` for another folder). Read the plan and the "To do by hand" list.
3. If the project has guard wrappers that don't import the SDK directly, pass them: `--include path/a.ts,path/b.ts` or `--guard-names fnA,fnB` (look for the functions the server entry point, middleware/proxy, health check, DB and job startup call).
4. Ask the user for the governing law and venue if the LICENSE doesn't have one yet; then run `apply` with `--governing-law "<text>"`. If a different LICENSE exists, ask before using `--replace-existing`.
5. Do the to-dos the command lists:
   - Boot log line: `console.log("[Daywalker] Running under Source-Available License. Quota managed via @shelbyb/daywalker-sdk.")` once at server start, server runtime only, not during builds (Next.js: `register()` in `instrumentation.ts`, guarded by `NEXT_RUNTIME === "nodejs"`; plain Node: the entry file).
   - Bundler: keep the notice header as a banner comment (tsup/esbuild `banner: { js }`, Vite/Rollup `output.banner`, Webpack `BannerPlugin({ banner, raw: true })`) and copy `LICENSE` to the output directory (tsup `onSuccess`, Vite plugin, or a build script).
   - Dockerfile: `COPY LICENSE` into the final image.
6. Verify: `npx -p @shelbyb/daywalker-sdk@latest daywalker license check` must exit 0 (the governing-law line shows as a to-do until set). Run the project's lint, typecheck and fast tests for touched files and any SDK integrity check it has. If a bundler is configured, run it and confirm the banner and `dist/LICENSE` appear.
7. Report: files changed, packages still `private`, open to-dos (governing law, counsel review), and that nothing is committed. Suggest adding `daywalker license check` to CI.
