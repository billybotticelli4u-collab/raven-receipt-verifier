# Frozen Ed25519 contract (Agent A) — write before further edits

Profile name: **libsodium `crypto_sign_verify_detached`**

## VERIFY invariant

A receipt/signature is accepted only if the Ed25519 public key and signature
satisfy the Raven Ed25519 profile (libsodium `crypto_sign_verify_detached`)
consistently across all implementations.

Accepted only when ALL hold:
1. Key wire form is canonical RFC 4648 Base64 (padded; re-encode identity).
2. Key DER is exact RFC 8410 Ed25519 SPKI (`302a300506032b6570032100` ‖ 32 raw).
3. Raw public key A is a **canonical** curve encoding (y < p; re-encode byte-identical).
4. A does **not** have small order (order dividing 8): `[8]A ≠ O` fails ⇒ reject.
5. Signature is 64 bytes; R is a canonical curve encoding; scalar S is in `[0, L)`.
6. Detached verify under the profile succeeds.

Malformed encodings, identity/small-order/non-prime-subgroup points, non-canonical
scalar/signature forms, or any case outside this profile MUST fail closed
**before or at** the crypto boundary. Backend-specific permissiveness MUST NOT
change the Raven verdict.

## TRUST-LOAD invariant

A key that would be rejected by the verifier profile MUST also be rejected when
loaded as a trusted key. Trust configuration MUST NEVER turn a structurally
invalid Ed25519 key into an acceptable trust anchor.

Operationally: every member of `trustedKeys` must classify as profile-supported
(`classifyTrustKey` / `raw_key_from_spki_base64` + domain assert). Invalid or
unsupported members ⇒ `trust_config_invalid` (or Python equivalent fail-closed).

## KEYGEN invariant

Raven-generated Ed25519 keys MUST always fall inside the verifier/trust-loader
accepted domain and round-trip through every implementation (SPKI export →
domain assert → verify of a fresh signature → accept as trustedKeys member).

## Out of scope (firewall)

No workflow/publish/OIDC/engine-floor/deploy/trust-anchor-rotation/receipt-v1
schema/unrelated refactor.
