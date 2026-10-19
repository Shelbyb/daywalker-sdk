/**
 * The text `daywalker license apply` installs. LICENSE_TEXT was reviewed and redrafted from the original
 * custom license (see docs/license.md); it is not legal advice, and the governing-law line is an owner decision.
 */

/** The placeholder in LICENSE_TEXT that `--governing-law` replaces. */
export const GOVERNING_LAW_PLACEHOLDER = "[GOVERNING LAW / VENUE: owner to\ndecide]";

export const LICENSE_TEXT = `DevPulse Source-Available License, Version 1.0

Copyright (c) 2026 Shelby Thomas Brayton Jr. / Shelby Tech LLC.
All rights not expressly granted in this license are reserved.

ACCEPTANCE

By using, copying, modifying or distributing the Software, You agree to the
terms of this license. If You do not agree, You have no rights under it.

DEFINITIONS

"Licensor" means Shelby Tech LLC and Shelby Thomas Brayton Jr., the copyright
holders of the Software.

"Software" means the source code, object code, documentation and other files
that the Licensor makes available under this license, and any portion of
them.

"You" means the individual or legal entity exercising rights under this
license. If You act on behalf of an entity, "You" includes that entity and
any entity that controls, is controlled by, or is under common control with
it.

"SDK" means the npm package \`@shelbyb/daywalker-sdk\`, including any version
or successor the Licensor designates for use with the Software.

"License Key Functionality" means the Software's integration with the SDK and
all logic, calls, hooks and data used for license-key verification, quota
metering, usage reporting to the Licensor, and rate limiting, together with
the licensing notice headers and the startup log line that identify that
integration.

"Free Tier" means use of the Software under a free license key issued by the
Licensor, within the quotas, rate limits and single-service allowance the SDK
enforces for that key.

"Commercial Tier" means a paid subscription or license obtained from the
Licensor under a separate written agreement, which may unlock premium
features, higher quotas or rate limits, and multi-service deployments.

"Service" means one deployed instance or logical application of the Software
as identified by the SDK.

1. LICENSE GRANT

Subject to Your compliance with the limitations and conditions in this
license, the Licensor grants You a non-exclusive, royalty-free, worldwide,
non-sublicensable, non-transferable license to:

  (a) view, use, copy and self-host the Software;
  (b) prepare modifications and derivative works of the Software; and
  (c) distribute the Software and Your modifications and derivative works,

in each case only as permitted by Sections 2 and 3.

2. LIMITATIONS

  (a) No circumvention. You may not move, change, disable, remove, bypass,
      stub out, spoof or otherwise circumvent the License Key Functionality,
      and You may not remove or obscure any functionality in the Software
      that is protected by a license key. Circumvention includes, without
      limitation: deleting or replacing the SDK or its calls; substituting a
      mock, fork or patched SDK; forging, sharing or reusing license keys or
      verification responses; blocking or redirecting the SDK's
      communication with the Licensor; altering quota or rate-limit values;
      and splitting one deployment into several to evade the single-service
      allowance.

  (b) Licensed use only. You may use the Software only with a valid license
      key verified through the SDK. Without a Commercial Tier, Your use is
      limited to the Free Tier. Premium features, quotas or rate limits
      above the Free Tier, and running more than one Service require an
      active Commercial Tier.

  (c) No removing notices. You may not alter, remove or obscure any
      licensing, copyright or other notices of the Licensor in the Software,
      including the notice headers and startup log line described above.

3. DISTRIBUTION AND MODIFICATIONS

If You distribute the Software or any modification or derivative work of it,
in source or object form, You must:

  (a) include a complete copy of this license, or a link to it, and retain
      all copyright, licensing and attribution notices;
  (b) keep the License Key Functionality intact and functional;
  (c) mark modified files with a prominent notice that You changed them; and
  (d) not impose any terms that conflict with or add to this license.

Each recipient receives a license to the Software directly from the Licensor
under these terms. You may not sublicense the Software, and Your own
modifications may be licensed by You only on terms that do not permit
anything this license prohibits.

4. PATENTS

The Licensor grants You a license, under any patent claims it can license or
becomes able to license, to make, have made, use, sell, offer for sale,
import and have imported the Software, in each case subject to the
limitations and conditions in this license. This license does not cover any
patent claims that You cause to be infringed by modifications or additions
to the Software. If You or Your company make any written claim that the
Software infringes or contributes to infringement of any patent, Your patent
license for the Software granted under this license ends immediately.

5. TRADEMARKS

This license grants no rights in the Licensor's names, logos or trademarks,
including "DevPulse", "Daywalker", "Shelby Tech" or any related marks,
except as needed to reproduce the notices required by this license.

6. THIRD-PARTY COMPONENTS

Components of the Software provided by third parties remain subject to their
own licenses, which govern Your use of those components. The SDK is licensed
under its own terms.

7. TERMINATION

If You use the Software in violation of this license, Your license ends
automatically. If the Licensor notifies You of a violation and it is Your
first notice, Your license is reinstated retroactively if You cure the
violation within 30 days after receiving notice. If You receive a second
notice of any violation, or do not cure within 30 days, Your license ends
permanently unless the Licensor reinstates it in writing. Sections 5, 6, 8,
9 and 10 survive termination.

8. NO WARRANTY

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.

9. LIMITATION OF LIABILITY

TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL THE LICENSOR OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR
IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

10. GENERAL

This license is governed by the laws of [GOVERNING LAW / VENUE: owner to
decide], excluding its conflict-of-laws rules. A Commercial Tier agreement
prevails over this license to the extent they conflict. If any provision is
held unenforceable, the rest remains in effect. The Software is
source-available; it is not open source software.
`;

/** Present in every notice header; `check` and `apply` look for it. */
export const HEADER_MARKER = "Licensed under the terms of the LICENSE file located in the root directory.";

/** Prepended to files that import the SDK or call its guards (block comment, so it works in JS and TS). */
export const HEADER_COMMENT = `/*
 * Copyright (c) 2026 Shelby Thomas Brayton Jr.
 * ${HEADER_MARKER}
 *
 * NOTICE: Removal or modification of @shelbyb/daywalker-sdk imports or
 * telemetry verification calls in this file constitutes a direct breach of license.
 */
`;

export const BOOT_NOTICE = "[Daywalker] Running under Source-Available License. Quota managed via @shelbyb/daywalker-sdk.";

export const README_SECTION = `## License
This project is licensed under the **DevPulse Source-Available License** (source-available, not open source).
It is free to view, self-host, and modify, but requires \`@shelbyb/daywalker-sdk\`
for license verification and rate-limiting enforcement. See [LICENSE](./LICENSE) for details.
`;
