# EXPORTED_FILE_MANIFEST — raven-receipt-verifier release-control public source

Generated: 2026-09-15 (Europe/Rome / CEST).
Purpose: single-package public release source for `raven-receipt-verifier@0.1.0`,
derived from private `-launchguard` tip `0b01458` via Owner-prepared allowlist export.
This file is release-control metadata; it is **not** packed into the npm tarball.

## Private baseline (read-only reference)

| Field | Value |
| --- | --- |
| Private repo | `billybotticelli4u-collab/-launchguard` (PRIVATE; do not flip visibility) |
| Private path | `packages/verify-js` |
| origin/main HEAD | `0b01458fdc96be47fdc17e23085c3006be7440f8` |
| TREE | `f8f0c2aae5becc42f0be4e88f85365c0eede0c3c` |
| Export tarball | `verify-js-allowlist-export-0b01458.tar.gz` |
| Public repo | `billybotticelli4u-collab/raven-receipt-verifier` |
| Branch | `billy/release-control-public-source-0b01458-2026-09-15` |

## Allowlist files (single-package root)

Count: **126** paths from `ALLOWLIST_VERIFY_JS.txt` (PRIVATE_BASELINE.txt excluded).

| path |
| --- |
| `LICENSE` |
| `README.md` |
| `SECURITY.md` |
| `fixtures/holder-outcome-v1.json` |
| `fixtures/receipt-evm-v1/canonical-ordering-evm.json` |
| `fixtures/receipt-evm-v1/d7-ec-evm.json` |
| `fixtures/receipt-evm-v1/d7-rsa-evm.json` |
| `fixtures/receipt-evm-v1/forbidden-word-evm.json` |
| `fixtures/receipt-evm-v1/tampered-disclaimer-evm.json` |
| `fixtures/receipt-evm-v1/tampered-finding-evm.json` |
| `fixtures/receipt-evm-v1/unparseable-timestamp-evm.json` |
| `fixtures/receipt-evm-v1/valid-minimal-evm.json` |
| `fixtures/receipt-evm-v1/valid-stale-evm.json` |
| `fixtures/receipt-evm-v1/valid-usdc-base-testkey.json` |
| `fixtures/receipt-evm-v1/wrong-domain-evm.json` |
| `fixtures/receipt-evm-v1/wrong-key-evm.json` |
| `fixtures/receipt-v1/canonical-ordering.json` |
| `fixtures/receipt-v1/forbidden-word.json` |
| `fixtures/receipt-v1/production-receipt-v1-bonk-2026-07-03.json` |
| `fixtures/receipt-v1/production-receipt-v1-bonk-verified.json` |
| `fixtures/receipt-v1/rules-1.1.2-no-holder-historical.json` |
| `fixtures/receipt-v1/rules-1.1.3-holder-bearing-derived-compatibility.json` |
| `fixtures/receipt-v1/rules-1.1.3-no-holder-historical.json` |
| `fixtures/receipt-v1/rules-1.1.3-production-shaped-historical.json` |
| `fixtures/receipt-v1/rules-1.1.4-acp-bypass-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-attempt-state-type-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-attempt-type-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-duplicate-unresolved-compound-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-empty-coverage-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-malformed-reason-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-missing-attempt-field-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-missing-provenance-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-mutated-signed-provenance.json` |
| `fixtures/receipt-v1/rules-1.1.4-observed-unresolved-contradiction.json` |
| `fixtures/receipt-v1/rules-1.1.4-primary-adjustment-contradiction-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-slot-mismatch-invalid.json` |
| `fixtures/receipt-v1/rules-1.1.4-state-a-valid.json` |
| `fixtures/receipt-v1/rules-1.1.4-state-b-valid.json` |
| `fixtures/receipt-v1/rules-1.1.4-state-c-valid.json` |
| `fixtures/receipt-v1/rules-future-unsupported.json` |
| `fixtures/receipt-v1/rules-version-malformed.json` |
| `fixtures/receipt-v1/tampered-disclaimer.json` |
| `fixtures/receipt-v1/tampered-finding.json` |
| `fixtures/receipt-v1/unparseable-timestamp.json` |
| `fixtures/receipt-v1/valid-minimal.json` |
| `fixtures/receipt-v1/valid-stale.json` |
| `fixtures/receipt-v1/valid-with-findings.json` |
| `fixtures/receipt-v1/wrong-domain.json` |
| `fixtures/receipt-v1/wrong-key.json` |
| `package-lock.json` |
| `package.json` |
| `scripts/clean-dist.mjs` |
| `scripts/test-cjs-consumer.mjs` |
| `scripts/test-declaration-consumer.mjs` |
| `scripts/test-packed-install.mjs` |
| `src/canonicalDataSnapshot.ts` |
| `src/canonicalJson.ts` |
| `src/detect.ts` |
| `src/ed25519KeyDomain.ts` |
| `src/ed25519NodeVerify.ts` |
| `src/index.ts` |
| `src/keyManifest.ts` |
| `src/outcomeProjection.ts` |
| `src/proposed.ts` |
| `src/receiptEvmV1.ts` |
| `src/receiptRules.ts` |
| `src/receiptV1.ts` |
| `src/solanaAddress.ts` |
| `src/trustAnchor.ts` |
| `src/verifyReceiptEvmV1.ts` |
| `src/verifyReceiptV1.ts` |
| `src/verifyReceiptV1ForSubject.ts` |
| `test/canonicalDataSnapshot.test.ts` |
| `test/canonicalJson.test.ts` |
| `test/detect.test.ts` |
| `test/ed25519-corpus/AGENT_A_REPAIR_REPORT.md` |
| `test/ed25519-corpus/FROZEN_CONTRACT.md` |
| `test/ed25519-corpus/README.md` |
| `test/ed25519-corpus/RESULT_acp.json` |
| `test/ed25519-corpus/RESULT_browser-blink.json` |
| `test/ed25519-corpus/RESULT_browser-receipt-page.json` |
| `test/ed25519-corpus/RESULT_for-subject.json` |
| `test/ed25519-corpus/RESULT_python.json` |
| `test/ed25519-corpus/RESULT_standalone-raven-receipt-verifier.json` |
| `test/ed25519-corpus/RESULT_unrepaired-backend.json` |
| `test/ed25519-corpus/RESULT_verify-js.json` |
| `test/ed25519-corpus/contract-freeze/BACKEND_INDEPENDENCE.json` |
| `test/ed25519-corpus/contract-freeze/CONTRACT_FREEZE_HANDOFF.md` |
| `test/ed25519-corpus/contract-freeze/CROSS_RUNTIME_DISAGREEMENTS.json` |
| `test/ed25519-corpus/contract-freeze/CROSS_RUNTIME_TABLE.md` |
| `test/ed25519-corpus/contract-freeze/PARENT_RED_SUMMARY.json` |
| `test/ed25519-corpus/contract-freeze/SURFACE_IDENTITY.json` |
| `test/ed25519-corpus/contract-freeze/TRUST_KEYGEN_MUTANTS.json` |
| `test/ed25519-corpus/contract-freeze/run_backend_indep.mjs` |
| `test/ed25519-corpus/contract-freeze/run_trust_keygen_mutants.mjs` |
| `test/ed25519-corpus/corpus.mjs` |
| `test/ed25519-corpus/corpus_baseline.json` |
| `test/ed25519-corpus/ed25519_corpus.json` |
| `test/ed25519-corpus/parent-baseline/PARENT_BACKEND.json` |
| `test/ed25519-corpus/parent-baseline/PARENT_JS_KERNEL.json` |
| `test/ed25519-corpus/parent-baseline/PARENT_PYTHON.json` |
| `test/ed25519-corpus/parent-baseline/run_backend.mjs` |
| `test/ed25519-corpus/parent-baseline/run_backend_local.mjs` |
| `test/ed25519-corpus/parent-baseline/run_parent_js_kernel.mjs` |
| `test/ed25519-corpus/parent-baseline/run_parent_python.py` |
| `test/ed25519-corpus/run_corpus.mjs` |
| `test/ed25519-corpus/run_surface.mjs` |
| `test/exportSurface.test.ts` |
| `test/fixture-parity.test.ts` |
| `test/helpers/readmeTrustContract.ts` |
| `test/hostileReceipt.test.ts` |
| `test/keyManifest.test.ts` |
| `test/noncanonicalSignerKey.test.ts` |
| `test/readmeTrustContract.test.ts` |
| `test/receiptIdTamper.test.ts` |
| `test/releaseManifest.test.ts` |
| `test/signatureKeyType.test.ts` |
| `test/subjectBinding.test.ts` |
| `test/trustAnchor.test.ts` |
| `test/trustConfig.test.ts` |
| `test/trustConfigPrototype.test.ts` |
| `test/trustConfigShapeFailure.test.ts` |
| `test/unexpectedTopLevelField.test.ts` |
| `test/vectors-evm.test.ts` |
| `test/vectors.test.ts` |
| `tsconfig.build.json` |

## Release-control additions (not from allowlist export)

| path | role |
| --- | --- |
| `.gitignore` | BUILD_SUPPORT |
| `.github/workflows/verify-js-first-publish.yml` | FIRST_PUBLISH control (ceremony BLOCKED) |
| `EXPORTED_FILE_MANIFEST.md` | this manifest |
| `RELEASE_CONTROL.md` | ceremony / blocker status |
| `scripts/test-packed-ed25519-corpus.mjs` | packed Ed25519 corpus gate |
| `scripts/negative-control-pack-identity.mjs` | mutate/restore pack-identity negative control |
| `scripts/test-registry-absent-shapes.py` | CONTROL_PY registry_absent npm 404 shape unit/control |

## Metadata delta vs private tip

- `package.json` `repository` set to `https://github.com/billybotticelli4u-collab/raven-receipt-verifier.git`
  (absent on private tip). This **changes** packed `package.json` bytes and therefore decoded-tar.
- Do **not** reuse private-tip decoded-tar `0be0a2c3…18b0` after this metadata edit.

## Standalone adaptations (public single-package)

Allowlist tests that hard-require private monorepo peers are made skip-safe here
(same class as existing `fixture-parity.test.ts` skip):

- `test/vectors.test.ts` — lazy-load `apps/raven-solana-holders` + `apps/raven-solana-outcome`; skip three cross-surface tests when absent
- `test/readmeTrustContract.test.ts` — skip python README guard when `reference-verifiers/python` is absent

These adaptations do **not** change packed runtime bytes (`files` / `dist` / `package.json` publish surface).
