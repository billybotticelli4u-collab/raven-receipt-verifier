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

Measured locally on 2026-09-23 (Europe/Rome) after setting:

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
| Decoded-tar SHA-256 | `6764b02da729d502b6b3cb0072366fe0cb23ab46829d4b53e3afecb99bd63520` |
| Archive SHA-256 (host gzip; transport only) | `848d13d3cc6483ded1711a015c74a7421571368fa2a43ec2325c1364ab556d62` |
| npm integrity | `sha512-hhyKHfXMPYeCe3LRSq3q4u+H/PpQ4Tg2h7DH1Hf/mSgBhjHH3asyrYTVevjAOIr7qPR+zgikdIweF7IXUjs6eA==` |
| Sorted member-hash manifest SHA-256 | `b2141bdf2fb547d65acd35905ba723506670e8276efb98e6100ea37fe80d9d21` |
| Reviewed private candidate decoded-tar (no repository; do not reuse) | `aa1be924d0f22e25c756a62a687be90ac7dcf7ed3ae98268e149657fa5154a18` |

Cross-build equivalence uses **decoded-tar**, never gzip archive identity.
The public successor and reviewed private candidate have the same 56-member allowlist;
55 members are byte-identical. The only packed difference is `package/package.json`, where
the public successor adds the matching public `repository` field.

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

1. Independent review of this public tree ↔ decoded-tar `6764b02d…3520` and Ed25519 packed corpus (0-forgeable expected).
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
