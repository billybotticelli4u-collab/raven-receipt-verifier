# Security policy

`raven-receipt-verifier` is verification-only: no signer, no scanner, no
network access, no advice. Its security properties are the ones worth
reporting:

- a receipt it accepts as `valid` whose signature does not verify;
- `keyTrusted` becoming `true` from anything other than caller-supplied pins;
- subject binding accepting a receipt for a different chain/mint/program;
- any path that converts missing evidence into a pass.

## Reporting

Report vulnerabilities using the private security contact published at
https://ravenattest.com/.well-known/security.txt (RFC 9116) and mirrored on
Raven's security page, https://ravenattest.com/security.html. Do not open
public issues for unpublished vulnerabilities. Never include private keys,
seed phrases, API keys, or customer data in an initial report — we will
never ask for them.

## Scope notes

- Verification never fetches: key trust is caller-pinned, staleness is
  reported against the receipt's own `maxAgeSeconds`, and coverage gaps are
  first-class fields. A `valid` receipt is a statement about signature
  integrity and payload binding — signer trust, freshness, and policy remain
  the caller's separate decisions.
