# raven-receipt-verifier — public source (unpublished)

This repository is the **public, historyless source** for the intended npm package
`raven-receipt-verifier`: an open, dependency-free local verifier for Raven **receipt-v1**.

**Source only, not yet published to npm.** On 2026-11-02, the public registry lookup
for `raven-receipt-verifier` returned HTTP 404. The `0.1.0` version in this tree names
a source candidate, not an available registry release.

This repository lets engineers read, build and test that source without depending
on Raven's private development monorepo. Local checks do not authorize publication.

## What is here

| Path | Why it is here |
| --- | --- |
| `packages/verify-js/` | Unpublished package source, tests, fixtures, lockfile and build config. |
| `apps/raven-solana-holders/`, `apps/raven-solana-outcome/` | Cross-implementation parity oracles required by `test/vectors.test.ts` (43 of 209 tests). Test-only — never shipped in the tarball. |
| `apps/launchguard-acp/fixtures/receipt-v1/` | Golden vectors the package's fixture-parity test compares against. Test-only. |
| `.github/workflows/verify-js-publish.yml` | Reserved publication workflow (OIDC provenance, protected environment); its presence does not mean a release exists or publication is authorized. |
| `ops/` | Permanent mirror-boundary and workflow-security controls. |
| `release/release-identity.json` | Recorded candidate tarball identity; not evidence of a published package. |

This repository carries **no** development history, operator records, CRM or outreach
material, deployment configuration, or production secrets.

## Review the source

From the repository root, with a supported Node version and the development
dependencies available from the registry or a populated cache:

```sh
npm --prefix packages/verify-js ci
npm --prefix packages/verify-js run build
npm --prefix packages/verify-js test
```

These commands build and test this source checkout. They do not download a
published Raven verifier or establish a released package's integrity. Any future
release needs separate review, freshly measured archive pins and publication
authorization; the existing recorded pins must not be reused for changed bytes.

## Trust boundary

For a future package published with npm provenance, provenance would authenticate
**package/source lineage** — that its tarball was built from this repository.
It would **not** tell you which Raven signer key to trust. Initial signer
trust comes from your authenticated Raven onboarding handoff, which names the exact package
version, integrity, and key material. The same-host `/pubkey` endpoint and the public
security page are discovery and cross-check surfaces, not trust roots.

Security contact: see `packages/verify-js/SECURITY.md`.
