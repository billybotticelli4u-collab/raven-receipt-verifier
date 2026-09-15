# Agent A — Ed25519 key-domain repair

## Named semantics
**libsodium `crypto_sign_verify_detached`**

Canonicalize point encoding first; reject small-order public keys; reject non-canonical scalar `S`. Applied before any backend `crypto.verify` / WebCrypto call. Non-canonical base64 remains a trust-identity property via the existing canonical base64 decoder (same place, before backend).

## Surface enumeration (before edit)

| Surface | Path | Role |
|---|---|---|
| verify-js kernel | `packages/verify-js/src/verifyReceiptV1.ts` | Solana receipt-v1 verify |
| ForSubject wrapper | `packages/verify-js/src/verifyReceiptV1ForSubject.ts` | subject-binding wrapper over kernel |
| EVM kernel (same package) | `packages/verify-js/src/verifyReceiptEvmV1.ts` | EVM receipt verify |
| keyManifest | `packages/verify-js/src/keyManifest.ts` | rotation chain verify |
| standalone package | `packages/verify-js` → `raven-receipt-verifier` | packed npm surface (same kernel) |
| browser blink | `apps/raven-blink/public/receipt-verify.js` | browser copy |
| browser receipt-page | `apps/raven-receipt-page/public/receipt-verify.js` | browser copy (byte-identical twin) |
| ACP copy | `apps/launchguard-acp/src/receipt/verifyReceiptV1.ts` | ACP verifier copy |
| ACP keygen | `apps/launchguard-acp/src/acp/attestationSigner.ts`, `hosted/attestationV2Signer.ts` | refuse emitting bad keys |
| Python reference | `reference-verifiers/python/raven_verify.py` | independent reference |

## Predicate application points
1. **Verification** — `decodeCanonicalEd25519Spki` + signature domain assert before `crypto.verify` / `subtle.verify` / Python `ed25519_verify`
2. **Trust-config load** — `classifyTrustKey` / `raw_key_from_spki_base64` reject hostile pins when configured
3. **Key generation/rotation** — generate helpers assert exported SPKI domain; keyManifest verify uses the same asserts

## Corpus
`raven-ed25519-corpus` v1.0.0 vendored at `packages/verify-js/test/ed25519-corpus/` (unchanged vectors).

## Results at TRIALS=256

| Surface | forgeable_within_budget | positives_accepted | pass |
|---|---|---|---|
| unrepaired-backend (baseline) | 27 | 100 | no |
| verify-js | 0 | 100 | yes |
| for-subject | 0 | 100 | yes |
| standalone-raven-receipt-verifier | 0 | 100 | yes |
| browser-blink | 0 | 100 | yes |
| browser-receipt-page | 0 | 100 | yes |
| acp | 0 | 100 | yes |
| python | 0 | 100 | yes |

## Engine floor
**Not changed.** Measurement: with the Raven-level libsodium key-domain predicate in front of OpenSSL/`crypto.verify`, the forgery class is closed on Node 25.8.1 in this worktree (0/69 forgeable @ 256 trials). Raising `engines` remains an **unproven** remedy and was not used.

## Firewall
No `.github/` / workflow changes. No receipt-v1 schema / payload hash / receiptId / signed-body changes. No publish. No tag. No self-merge.
