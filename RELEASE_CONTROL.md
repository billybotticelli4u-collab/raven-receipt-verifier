# RELEASE_CONTROL — raven-receipt-verifier first publish

**Status:** first publish **BLOCKED**; ceremony **BLOCKED**.

This public repository is the Owner-authorized **release-control successor** for truthful npm
provenance. It is **not** authorization to publish.

## Hard holds (must remain until Owner clears each)

| Hold | Value | Effect |
| --- | --- | --- |
| `FIRST_PUBLISH_CEREMONY` | `BLOCKED` | Workflow `publish_bootstrap` refuses publication. Dispatch inputs cannot clear this. |
| First publish | BLOCKED | No `npm publish` until ceremony + independent review + Owner GO. |
| PR #211 | DO NOT TOUCH | Private `-launchguard` draft held; not this path. |
| Private `-launchguard` | READ-ONLY / PRIVATE | Do not merge publish workflows there; do not flip visibility. |

## Measured pack identity (after `repository` field)

Measured locally on 2026-09-15 (Europe/Rome) after setting:

```json
"repository": {
  "type": "git",
  "url": "https://github.com/billybotticelli4u-collab/raven-receipt-verifier.git"
}
```

| Field | Value |
| --- | --- |
| Package | `raven-receipt-verifier@0.1.0` |
| Members | `56` |
| Decoded-tar SHA-256 | `74df0f57e9e93c5b06552651b9a0003091e2dd11541aae750339d9cc9eb852a5` |
| Archive SHA-256 (host gzip; transport only) | `bd9930ecc294f56ec1d1517a712c9a91aeac8ec5781cf1dfb12011c1415abd69` |
| npm integrity | `sha512-++wAs2Maekm/7bpDSXfN1Uhm+WZr9AETQRCPZpECDYYucI0ReuO8m2IpNvWHhzUvTyLlSq7bxHmiWrAF4ocd6Q==` |
| Content fingerprint | `297a3ced56cddc687700c3b7398e0da7fb5ec51fc586677d5e06520ddffa9eb2` |
| Private tip decoded-tar (no repository; do not reuse) | `0be0a2c36e6e611ff6d7bbe64235bd6225b5207d38368100a39c52769a5218b0` |

Cross-build equivalence uses **decoded-tar**, never gzip archive identity.

## Workflow

- File: `.github/workflows/verify-js-first-publish.yml`
- Modes: `validate_only` (default) vs `publish_bootstrap`
- While `FIRST_PUBLISH_CEREMONY=BLOCKED`, `publish_bootstrap` refuses before any credential use
- When later unblocked by repository-file change + review: `npm publish … --provenance --access public`
- Token: Environment secret **name only** (`NPM_BOOTSTRAP_TOKEN` on environment `npm-release`); no token in source
- npm CLI floor: `>=11.5.1` (pinned `11.18.0` in workflow)
- Node matrix: `22.18.0`, `24.20.0`
- Pack once; seal decoded-tar; publish consumes the sealed artifact only

## Ceremony steps remaining (Owner / Glen)

1. Independent review of this public tree ↔ decoded-tar `74df0f57…52a5` and Ed25519 packed corpus (0-forgeable expected).
2. Owner GO / no-GO on first publication (this document is not GO).
3. Confirm public repo remains the provenance source (not private `-launchguard`).
4. Repository-file change only: set `FIRST_PUBLISH_CEREMONY` from `BLOCKED` to the reviewed clear value after pins/review match.
5. Create short-lived granular bootstrap token; place only in protected Environment `npm-release` as `NPM_BOOTSTRAP_TOKEN` (never in chat/repo).
6. Environment required-reviewer approval on the exact `publish_bootstrap` run (prevent_self_review remains).
7. Dispatch `publish_bootstrap` on the reviewed SHA only; observe registry 201 + provenance attestation.
8. Cold-install public tarball; verify integrity/decoded-tar; then Owner 2FA trusted-publisher setup; revoke bootstrap token.

Failure after registry mutation is an **incident**, not a retry/unpublish.

## Explicit non-goals for this PR

- No npm publish
- No merge to `main` without independent review + Owner GO
- No credentials created/inspected
- No edits to private PR #211 or `-launchguard`
