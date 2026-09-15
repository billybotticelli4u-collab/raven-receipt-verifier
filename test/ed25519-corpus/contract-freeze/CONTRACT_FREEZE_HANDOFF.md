# Agent A — Ed25519 contract freeze handoff

**Status:** ready for independent review only. No self-GO. No merge.

## 1. Identities

| | |
|---|---|
| Branch | `billy/ed25519-key-domain-repair-2026-09-13` |
| Parent HEAD | `18b1a13c601cc362404dc6306fd8f4d1cc3e046e` |
| Parent TREE | `6bd7276fb71f8878bd9b3313d7200e56f447a0f3` |
| Repair commit (code) | `ed3bc24743ffe69b9cbbfa66636e800e3680f297` |
| Repair TREE | `0ab8c896a7a048043e6e4504766eff82d00ba0f9` |
| Evidence tip | _(this freeze commit)_ |

Frozen contract: `packages/verify-js/test/ed25519-corpus/FROZEN_CONTRACT.md`  
Profile: **libsodium `crypto_sign_verify_detached`**

## 2. Changed files (repair + evidence)

### Implementation
- `packages/verify-js/src/ed25519KeyDomain.ts` (new)
- `packages/verify-js/src/ed25519NodeVerify.ts` (new)
- `packages/verify-js/src/verifyReceiptV1.ts`
- `packages/verify-js/src/verifyReceiptEvmV1.ts`
- `packages/verify-js/src/keyManifest.ts`
- `packages/verify-js/src/index.ts`
- `apps/launchguard-acp/src/receipt/ed25519KeyDomain.ts` (byte-identical copy)
- `apps/launchguard-acp/src/receipt/verifyReceiptV1.ts`
- `apps/launchguard-acp/src/acp/attestationSigner.ts`
- `apps/launchguard-acp/src/hosted/attestationV2Signer.ts`
- `apps/raven-blink/public/receipt-verify.js`
- `apps/raven-receipt-page/public/receipt-verify.js` (byte-identical to blink)
- `reference-verifiers/python/raven_verify.py`
- `reference-verifiers/python/run_ed25519_corpus.py` (**measurement infra only**)

### Evidence / corpus vendor
- `packages/verify-js/test/ed25519-corpus/**` (corpus, RESULT_*, parent-baseline, contract-freeze)

## Exact surfaces / functions

| Surface | Files / functions | Distinct? |
|---|---|---|
| JS kernel | `verifyReceiptV1.ts`: `decodeCanonicalEd25519Spki`, `resolveKeyTrust`/`classifyTrustKey`, `verifyReceiptV1`; domain via `ed25519KeyDomain.ts` + `ed25519NodeVerify.ts` | YES (canonical) |
| ForSubject | `verifyReceiptV1ForSubject.ts` wraps kernel | NO separate crypto (wrapper) |
| Standalone | same `packages/verify-js` / `raven-receipt-verifier` | NO separate impl |
| Browser blink | `apps/raven-blink/public/receipt-verify.js` | YES copy (inlined domain) |
| Browser receipt-page | twin of blink | **byte-identical** SHA-256 `da031ae6…` |
| ACP | `apps/launchguard-acp/src/receipt/verifyReceiptV1.ts` + `ed25519KeyDomain.ts` | domain **byte-identical** to verify-js `0ffac692…` |
| ACP keygen | `attestationSigner.ts`, `hosted/attestationV2Signer.ts` | assert on generate |
| Python | `reference-verifiers/python/raven_verify.py` | YES independent |
| Trust-load | `classifyTrustKey` / `normalizeTrustedKeys` / `resolveKeyTrust`; Python `raw_key_from_spki_base64` | shared predicates |
| Keygen | Node `generateKeyPairSync` + domain assert in ACP signers / keyManifest path | |

**Disclosure:** browser corpus runs exercised the shared TypeScript domain module path used to build/check the browser copies; they are not a live WebCrypto browser grind in-browser.

## 3. Parent RED (TRIALS=256)

| Surface | forgeable_within_budget | positives_accepted |
|---|---:|---:|
| unrepaired backend / OpenSSL | **27** | 100 |
| parent JS kernel (no small-order) | **27** | 100 |
| parent Python | **21** | 100 |

Failing classes (backend/JS): `small_order_key` 19 + `noncanonical_key_encoding` 8 = 27.  
Python: `small_order_key` 19 + `noncanonical_key_encoding` 2 = 21 (Python already refused more B_ aliases).

Artifacts: `parent-baseline/PARENT_*.json`

## 4. Final corpus table (post-repair, TRIALS=256)

| Surface | forgeable | positives | pass |
|---|---:|---:|---|
| verify-js | 0 | 100 | yes |
| ForSubject | 0 | 100 | yes |
| standalone | 0 | 100 | yes |
| browser-blink | 0 | 100 | yes |
| browser-receipt-page | 0 | 100 | yes |
| ACP | 0 | 100 | yes |
| Python | 0 | 100 | yes |

Cross-runtime: `CROSS_RUNTIME_TABLE.md` — **0 disagreements** across 169 vectors.  
Subject-binding: `subjectBinding.test.ts` **36/36** pass (unchanged semantics).

## 5. Trust-load matrix

From `TRUST_KEYGEN_MUTANTS.json`:
- hostile pin cases: **57**
- hostile pins rejected (`trust_config_invalid`): **57**
- genuine pin trusted: **true**

## 6. Keygen round-trip matrix

| Surface | domain_assert | verify | trust | round_trip_ok |
|---|---|---|---|---|
| node-generateKeyPairSync | ok | ACCEPT | trusted | **true** |
| assert-after-export | ok | ACCEPT | trusted | **true** |

## 7. Mutation results

| ID | Description | turns GREEN→RED |
|---|---|---|
| M0 | clean repaired | no (forgeable 0) |
| M1 | remove point-canon/small-order (OpenSSL only) | **yes** (forgeable 27) |
| M2 | permit non-canonical S / skip sig domain | **yes** vs permissive backend (10/12 hostile_sig ACCEPT; OpenSSL alone also refuses S≥L) |
| M3 | bypass trust-load classify | **yes** |
| M4 | bypass ForSubject (=kernel bypass) | **yes** (27) |
| M5 | bypass browser validation | **yes** (27) |
| M6 | bypass Python (=parent RED) | **yes** (21) |
| M7 | weaken keygen assert | **yes** (clean round-trip holds; mutant would skip) |

## 8. Semantic change beyond malformed rejection

**Yes, intentional profile semantics (frozen):**
1. Canonical curve encoding of A (y < p; re-encode identity).
2. Reject small-order A (`[8]A == O`).
3. Reject non-canonical scalar S (`S ≥ L`).
4. Same predicates on trust-load and keygen export.

Not changed: receipt-v1 schema, engines floor, workflows, publish, trust anchors.

## 9. Review readiness

**This exact tip is ready for independent review only.**  
Do not self-GO. Do not merge. Agent A STOP.

## Backend independence

`BACKEND_INDEPENDENCE.json`: of 57 hostile key encodings, Raven preconditions REFUSE all; OpenSSL alone may ACCEPT **27** (same forgery class as parent RED). Verdict is Raven precondition, not “Node happened to reject.”
