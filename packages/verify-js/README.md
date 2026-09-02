# raven-receipt-verifier

The open, **dependency-free** local verifier for Raven **receipt-v1**. Check a
signed on-chain-evidence receipt yourself — offline, with zero dependencies,
against an independently pinned signer key — and bind the receipt to the exact
token subject you asked about. You never have to trust Raven's servers to
trust a Raven receipt.

> **Verification is free and permissionless — forever.** Producing a receipt is the
> metered service; checking one is not. This package contains only verification: no
> signer, no scanner, no network, no advice. A receipt is signed evidence, not a
> verdict.

## Install

```sh
npm install raven-receipt-verifier
```

The published package exports compiled ESM and TypeScript declarations from
`dist/`; consumers do not need Node's TypeScript type-stripping support or a
TypeScript loader. Node 22.18 and later are supported (the release-plan
verified floor). The package is deliberately **ESM-only**: on the supported
Node floor, CommonJS consumers can `require()` it natively via Node's
require(esm) support, so no dual build is shipped.

## Trust bootstrap for the production key

For a customer path, npm provenance authenticates package/source lineage. It
does not tell you which Raven signer key you intended to trust.

Initial signer trust comes from an authenticated Raven commercial/onboarding
handoff that names the exact package identity (`raven-receipt-verifier`), the
exact version (`0.1.0`), and the exact package integrity digest for the bytes
you install. The embedded production anchor is the package pin carried by those
authenticated bytes:

```ts
import {
  RAVEN_PRODUCTION_TRUST_ANCHOR,
  ravenProductionTrustedKeys,
} from "raven-receipt-verifier";
```

`RAVEN_PRODUCTION_TRUST_ANCHOR[0].keyId` is
`rvk_c2997e90215279c2`, and
`ravenProductionTrustedKeys()` returns a fresh `Set<string>` containing the
anchored base64 SPKI key for offline verification.

`/pubkey` and the Raven security page are discovery and cross-check surfaces:
they should match the embedded anchor, but they are not the root of trust for a
receipt fetched from the same service. Likewise, `keyId` proves consistency with
the key material — not authenticity. Anyone can create a key and compute its own
`keyId`; the authenticated package/version/integrity handoff is what selects
the intended Raven production signer.

## What it does

The partner-facing entrypoint is
`verifyReceiptV1ForSubject(receipt, expectedSubject, options)`:

```ts
import {
  ravenProductionTrustedKeys,
  verifyReceiptV1ForSubject,
} from "raven-receipt-verifier";

// Use this only after your authenticated package/version/integrity handoff
// selected the package bytes you intended to trust.
const trustedKeys = ravenProductionTrustedKeys();

const result = verifyReceiptV1ForSubject(
  receipt,
  {
    // The exact subject you requested. All three fields are signed; all
    // three are compared. `chain` is the frozen 0.1.0 literal
    // "solana-mainnet" — the only namespace this release admits; any other
    // expected chain is expected_subject_invalid.
    chain: "solana-mainnet",
    mintAddress: "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263",
    tokenProgramAddress: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
  },
  { now: new Date(), trustedKeys },
);

if (
  result.valid && // structural + hash + receiptId + Ed25519 integrity
  result.keyTrusted && // signer is in YOUR independently pinned set
  !result.stale && // fresh enough for the receipt's own maxAgeSeconds
  result.subjectMatches === true && // evidence IS the subject you requested
  result.rulesStatus === "supported_valid"
) {
  // ...then apply YOUR policy over receipt.findings / coverageGaps / scope.
}
```

It returns the full kernel result plus a **separate subject axis**:

```ts
interface VerifyReceiptForSubjectResult extends VerifyReceiptResult {
  subjectMatches: boolean | null; // null = binding could not be evaluated
  subjectReasons: Array<
    | "expected_subject_invalid"        // your expected tuple was malformed
    | "receipt_subject_unavailable"     // the receipt's subject could not be read
    | "subject_chain_mismatch"
    | "subject_mint_mismatch"
    | "subject_token_program_mismatch"
  >;
}
```

The expected subject is a **closed** input: exactly the three own string-keyed
fields, both addresses canonical base58 encodings of exactly 32 decoded bytes.
Missing, extra, inherited, symbol-keyed or hostile (proxy/getter) shapes yield
`subjectMatches: null` + `expected_subject_invalid` — never an exception, and
never a silent match. Mismatch reasons are reported in stable
chain → mint → program order and are **never** folded into the integrity
`reasons` array.

Integrity verification and subject binding consume **one stable capture** of
the receipt: the wrapper detaches the caller's object once (descriptor-safe,
each declared field read exactly once, deeply frozen) before checking
anything, so a stateful getter or Proxy cannot show integrity one subject and
binding another. A receipt that cannot be captured fails closed with
`receipt_uninspectable`; the hostile source is never re-read.

The trust policy is **required** at this entrypoint: supply well-formed
`trustedKeys` or the explicit typed diagnostic opt-out
`allowUntrustedKey: true`. Omitting both, or passing a malformed policy,
returns `keyTrusted: false` with `trust_config_invalid` — the trust axis is
never silently absent.

## The lower-level kernel

`verifyReceiptV1(receipt, { now?, trustedKeys?, allowUntrustedKey? })` is the
integrity-only primitive: it answers "is this artifact an untampered Raven
receipt", not "is this the evidence I asked for". It runs the receipt-v1
verification procedure and returns:

```ts
interface VerifyReceiptResult {
  valid: boolean;      // gated ONLY by checks 1–5 below
  stale: boolean;      // freshness — reported, never gates `valid`
  reasons: string[];   // stable codes for every failed / noted check
  keyTrusted?: boolean; // present when `trustedKeys` or `allowUntrustedKey` is supplied
  rulesVersion: string | null;
  rulesStatus: "supported_valid" | "supported_invalid" | "unsupported" | "malformed" | null;
  rulesReasons: string[]; // signed-semantics axis; never folded into `valid`
}
```

Checks, in order (reasons accumulate; a tampered receipt surfaces every failure):

1. **Shape** — exact field set and types.
2. **Disclaimer** — byte-for-byte exact.
3. **Forbidden words** — defense-in-depth over signed strings (`safe`, `unsafe`,
   `legit`, `scam-free`, `approved`, `guaranteed`).
4. **Payload hash + receiptId** — recomputed over the canonical preimage.
5. **Signature** — Ed25519 over the domain-separated envelope.
6. **Key trust** *(non-fatal)* — is `signerPublicKey` in your `trustedKeys`?
   `trustedKeys` accepts a `Set<string>` or a plain string array (the shape any
   caller loading keys from JSON or env will hold). Every malformed value — a
   non-collection, or any non-string member — fails closed and typed:
   `keyTrusted: false` with `trust_config_invalid`, and no exception escapes.
   With no keys supplied, `allowUntrustedKey: true` is the typed opt-out
   (`key_trust_not_evaluated`) and `allowUntrustedKey: false` is a typed
   contract error (`trust_config_invalid`); at this kernel level, omitting
   both preserves the historical not-evaluated behavior (the partner wrapper
   above refuses omission instead). A non-boolean `allowUntrustedKey` —
   realistic for env-derived strings such as `"false"` — is malformed trust
   configuration and fails closed with `trust_config_invalid`; it never
   silently disables trust evaluation.
7. **Freshness** *(non-fatal)* — `stale = now − timestamp > maxAgeSeconds`.
8. **Exact rules semantics** *(separate axis)* — historical rules retain their
   recorded meaning; `raven-rules@1.1.4` holder provenance is checked; canonical
   future and malformed identities are reported as unsupported and malformed.

Receipt-v1 carries and signs `payloadHash` plus the derived `receiptId`. It
does **not** carry a replay hash or official attestation hash — those belong
to the legacy `/verify` attestation contract and are not reconstructed or
claimed here.

`valid`, `stale`, `keyTrusted`, `rulesStatus` and `subjectMatches` are
**independent** outputs. A stale receipt is still authentic; a signature from
an untrusted key is still a valid signature; a correctly signed receipt can be
semantically inadmissible under its recorded rules; a fully valid receipt can
still be evidence for a DIFFERENT token than the one requested. Never collapse
these axes into one boolean.

`classifyFindingCodesOutcome(findingCodes)` is an additive, offline
interpretation helper that implements the canonical Solana outcome precedence.
The holder outcome vector corpus tests it against the engine and the browser and
Python ports. Receipt-v1 does not sign outcome, reason, or trigger fields, so
`verifyReceiptV1` never infers or validates those absent claims.

## Public surface

The `0.1.0` export map is frozen to the Solana receipt-v1 kernel: the two
verifier entrypoints, canonical JSON, the rules evaluator, the outcome
projection, receipt constants/types, and structural namespace detection. The
source tree also carries receipt-evm-v1 and key-manifest modules labeled
**PROPOSED** (no production EVM signer or manifest exists); they are compiled
and conformance-tested but deliberately **not exported** from the package, so
this artifact makes no compatibility promise for them.

## Cross-language note (for future reference verifiers)

Canonical JSON here sorts object keys with JavaScript's default sort (UTF-16
code-unit order). Receipt object **keys are a fixed set of ASCII field names**, so
byte-order, code-point order, and UTF-16 code-unit order all coincide — a verifier
written in Rust/Go/Python may use its native string sort and stay conformant *for
this schema*. Do not add non-ASCII object keys without revisiting this.

## Non-goals

This package does **not**: request or produce receipts, sign anything, access
wallets, submit transactions, call the network, evaluate policy, or emit any
safe/unsafe judgment. The additive outcome helper only reproduces Raven's
deterministic finding-taxonomy projection; deciding what to do with verified
evidence lives elsewhere. Raven does not issue safe/unsafe verdicts.

## Tests

```
npm test              # vendored golden vectors, offline
npm run test:packed   # pack, install outside the repo, import, verify a real receipt
```

The fixtures under `fixtures/receipt-v1/` are the same golden vectors the in-app
verifier is tested against — including a real production-signed BONK receipt — so
this extracted kernel cannot silently diverge from production. The adjacent
`fixtures/holder-outcome-v1.json` file is the shared cross-port outcome
precedence corpus.
