# raven-receipt-verifier — public release source

This repository is the **public, historyless release source** for the npm package
`raven-receipt-verifier`: an open, dependency-free local verifier for Raven **receipt-v1**.

It exists so a customer can read, build, test and reproduce the exact package they install —
without depending on Raven's private development monorepo.

## What is here

| Path | Why it is here |
| --- | --- |
| `packages/verify-js/` | The published package: source, tests, fixtures, lockfile, build config. |
| `apps/raven-solana-holders/`, `apps/raven-solana-outcome/` | Cross-implementation parity oracles required by `test/vectors.test.ts` (43 of 209 tests). Test-only — never shipped in the tarball. |
| `apps/launchguard-acp/fixtures/receipt-v1/` | Golden vectors the package's fixture-parity test compares against. Test-only. |
| `.github/workflows/verify-js-publish.yml` | The trusted-publishing ceremony (OIDC provenance, protected environment). |
| `ops/` | Permanent mirror-boundary and workflow-security controls. |
| `release/release-identity.json` | The frozen tarball identity the publish workflow refuses to deviate from. |

This repository carries **no** development history, operator records, CRM or outreach
material, deployment configuration, or production secrets.

## Verify what you installed

```sh
npm pack raven-receipt-verifier@0.1.0
npm --prefix packages/verify-js ci && npm --prefix packages/verify-js test
```

Compare the shasum and integrity with `release/release-identity.json`.

## Trust boundary

npm provenance authenticates **package/source lineage** — that this tarball was built from
this repository. It does **not** tell you which Raven signer key to trust. Initial signer
trust comes from your authenticated Raven onboarding handoff, which names the exact package
version, integrity, and key material. The same-host `/pubkey` endpoint and the public
security page are discovery and cross-check surfaces, not trust roots.

Security contact: see `packages/verify-js/SECURITY.md`.
