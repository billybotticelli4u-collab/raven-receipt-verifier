# Raven hostile Ed25519 conformance corpus v1.0.0

Authored by the **review lane**, not the repair lane. Vectors and pass criteria only — no repair,
no implementation guidance. Drop into the R&D lane; CODEX's Phases 6, 7 and 8 are covered by this.

```
corpus.mjs            regenerates the corpus deterministically in structure (fresh keys each run)
ed25519_corpus.json   169 vectors: 69 hostile + 100 positive controls
run_corpus.mjs        runner + pass criterion
corpus_baseline.json  measured baseline of the UNREPAIRED backend path
```

## Pass criterion (this is the whole thing)

```
forgeable_within_budget === 0   AND   positives_accepted === 100
```

on **every** maintained surface — verify-js kernel, ForSubject wrapper, browser copies, ACP copy,
the standalone `raven-receipt-verifier`, and the Python reference — and on every runtime in the
supported range. Anything less is a partial repair.

## Measured baseline, unrepaired (Node 22.22.2 / OpenSSL 3.5.5)

```
hostile vectors that ACCEPT a forgery : 27 / 69
  small_order_key            19
  noncanonical_key_encoding   8
positive controls accepted            : 100 / 100
median grinds needed                  : 4
```

## The correction that matters — forgery is message-dependent, and that does not help you

My first pass tabulated single-message results and made it look as if only certain key/signature
combinations forge. Wrong. Under cofactorless verification the forgery succeeds with probability
**1/order(A)**, measured over 2000 random messages:

| signer key | `R=identity,S=0` | `R=order2,S=0` |
|---|---|---|
| identity (order 1) | **100.0%** | 0.0% |
| order 2 | 50.8% | 48.8% |
| order 4 | 25.1% | 25.4% |
| order 8 | 12.3% | 12.0% |

So **every** small-order key is forgeable; the attacker mutates one body field — a slot number will
do — and retries. Median 4 attempts, worst case ~8. Treat "only works for some messages" as
"works, after eight microseconds of grinding". This is why the runner grinds rather than testing
one message, and why a repair validated against single-message vectors would look green and be
broken.

## Vector classes

| prefix | class | what it tests |
|---|---|---|
| `A_` (32) | small-order key | all 8 canonical small-order encodings × 4 forged signatures |
| `B_` (12) | non-canonical key encoding | `y ≥ p` and sign-bit aliases onto small-order points — an 8-entry blacklist misses these |
| `C_` (12) | hostile signature | genuine prime-order key with `S=0`, `S=L`, `S=L+1`, `S=2²⁵⁵−1`, high-bit S, `S+L` malleability, small-order R, zeroed R, bit flip, truncated, extended |
| `D_` (10) | malformed key | P-256, RSA-2048, Ed448, X25519, raw 32 bytes, trailing byte, truncated SPKI, NULL AlgorithmIdentifier params, short key, empty |
| `E_` (3) | non-canonical base64 | unpadded, whitespace-injected, mangled tail bits — the trust-identity axis, not the crypto axis |
| `F_` (100) | genuine | independently generated keypairs signing real Raven preimages — the over-rejection guard |

## Using it

```
node run_corpus.mjs                # baseline, 64 grinds per hostile vector
TRIALS=256 node run_corpus.mjs     # stricter
```

To test a repaired surface, replace the `backend` adapter in `run_corpus.mjs` with a call into that
surface. Keep the classification coarse — REFUSE vs ACCEPT — so taxonomy differences between
surfaces do not mask a security failure. Report the reason separately if you want the taxonomy
locked too.

## Notes for whoever writes the repair

- The `C_` signature vectors are expected to refuse on a correct implementation already; they exist
  so that a repair which tightens key handling does not loosen signature handling by accident.
- The `E_` vectors are a *trust-identity* property, not a crypto property: two spellings of the same
  key must not both resolve to a pinned identity. They belong in the same predicate.
- The `F_` controls are the reason to run this before and after: an over-strict subgroup check that
  rejects legitimate keys is a worse outage than the defect it fixes.
- 100 positive controls is a floor, not a ceiling. Regenerate with `corpus.mjs` for fresh keys on
  every run so the suite is not memorising one keypair.
