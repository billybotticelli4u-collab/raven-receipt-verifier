# Evidence attribution correction — F2

The original `RESULT_*.json` files are retained byte-for-byte. Their `surface`
strings do not establish that the named implementation ran. This annotation
supersedes that interpretation and the surface-results section of
`AGENT_A_REPAIR_REPORT.md`; it does not alter receipt contracts or crypto policy.

| Historical label | Implementation actually executed by run_surface.mjs | Application result established? |
|---|---|---|
| unrepaired-backend | Node crypto.verify without Raven's key-domain predicate | No; detached baseline only |
| verify-js | packages/verify-js/src/ed25519NodeVerify.ts | No; detached predicate only |
| for-subject | same TS predicate | No; wrapper never called |
| standalone-raven-receipt-verifier | same TS predicate | No; packed entry point never loaded |
| browser-blink | same TS predicate in Node | No Chromium or app entry point |
| browser-receipt-page | same TS predicate in Node | No Chromium or app entry point |
| acp | same TS predicate in Node | No ACP application call |
| python | reference-verifiers/python/raven_verify.py, detached predicate and guards | No full receipt evaluation |

Repeated shared-predicate measurements are not independent implementations.
Historical negative rows ground over random 48-byte messages; they are not
browser measurements of the corpus's original signed messages. This correction
does not label the earlier numeric observations as new measurements.

## Current harness contracts

`run_surface.mjs` only executes `shared-node-predicate`, `unrepaired-backend`,
or `python`, with an explicit `executed_implementation` in its output. Requesting
any of the historical application labels returns `NOT_EXECUTED`, `pass:false`,
and exit 2. An unavailable Python process is an execution failure, not a refusal.
`OUT` is required, must be outside this repository, and may not overwrite a file.

Example (from this directory, with an existing external evidence directory):

```sh
SURFACE=shared-node-predicate TRIALS=256 OUT=/absolute/external/predicate.json node run_surface.mjs
```

`run_browser_applications.mjs` drives the real Blink fragment and receipt-fetch
flows and the receipt-page mint-submit flow in Chromium. It serves unmodified
product bytes locally, wraps the verifier import with a pass-through call recorder,
and records actual WebCrypto message bytes. Receipt delivery is routed test data,
not a measurement of the live backend. Other remote requests are blocked.

Every flow uses the 169 unchanged corpus messages (100 signature positives and
69 hostile vectors) and four explicit full-receipt controls. The corpus messages
are not hashes of the control receipt body: an ACCEPT signature must still yield
an invalid full receipt with `payload_hash_mismatch`. Genuine signed full receipts
must pass integrity; untrusted keys and stale receipts are recorded separately.
Fresh page navigation prevents stale-fragment execution. The receipt-page startup
demo is recorded and cleared before submission; receipt identity, caller stack,
delivery count and the hidden demo banner must bind the measured submission.

```sh
PLAYWRIGHT_MODULE=/absolute/path/to/playwright/index.mjs \
CHROMIUM_EXECUTABLE=/absolute/path/to/chromium \
OUT=/absolute/external/browser-results.json node run_browser_applications.mjs
```

Per-fixture outcomes, reasons, assertion failures, browser version, source hashes,
screenshots and totals are written outside the repository. Never copy reviewer
RESULT files or treat this procedure itself as a successful run. Fresh measured
results are delivered with the author candidate's external evidence packet.

## ACP reachability and parity

At the inspected base and this bounded correction, ACP's `verifyReceiptV1` is a
library with test callers, not a production application caller. The build smoke
explicitly loads it as an additional library root; that does not make it part of
the service's production call graph. Both signer modules are load-smoked without
loading credentials or invoking signing. No caller was added to manufacture a
historical ACP verification claim.

`test/evidence-surface-integrity.test.ts` enforces byte parity of the ACP/package
key-domain copies and the two browser verifier copies. These monorepo checks run
in the existing verify-js CI job. They establish byte equality, not execution
equivalence or a production call path. Disposable one-sided mutation evidence
belongs in the external candidate packet.
