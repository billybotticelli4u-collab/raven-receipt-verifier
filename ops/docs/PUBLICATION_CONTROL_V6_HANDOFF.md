# PUBLICATION-CONTROL v6 — TOCTOU seal hardening handoff

Authoring only. NOT a self-GO. No publish / merge / deploy / platform change performed.

## EXECUTIVE RESULT

**FROZEN FOR INDEPENDENT REVIEW — shared-tree verify→spawn TOCTOU closed; not full compromised-runner immunity.**

Exact CODE freeze: `57d018cf944fed39070126ae977a1e294bef76b5` / tree `74907277b5ed210c4586e522f865646403adb0f5` on `billy/publication-control-v6-toctou-seal`. Raven package subtree + `release/` byte-identity unchanged vs v5 base `1e55965e`.

## EXACT IDENTITY

| field | value |
|---|---|
| repo | `billybotticelli4u-collab/raven-receipt-verifier` |
| branch | `billy/publication-control-v6-toctou-seal` |
| freeze HEAD (CODE) | `57d018cf944fed39070126ae977a1e294bef76b5` |
| freeze TREE (CODE) | `74907277b5ed210c4586e522f865646403adb0f5` |
| base HEAD (v5) | `1e55965eada1a5bc470ad095f311e91bb1a79693` |
| base TREE (v5) | `0006d5e57b3a9725b6969557c605041a5dc15dc3` |
| packages/verify-js | `da56440a505f0730203e2a0b254112fe8d19c76a` unchanged |
| release/ | `9d0c4e8e9ed1e346f84e5d59590ab49f3a4c9160` unchanged |
| workflow | unchanged |

## PROBLEM REPRODUCTION

Exact v5 hostile writer on shared governed npm `publish.js`: 2/60 wins (attempts 4,9) on Node 24.18.0; KIMI prior 4/60. CLI was shared-tree absolute path.

## IMPLEMENTATION

Private gexec seal copy + re-measure + sealed CLI only + destroy. See commit 57d018cf ops diffs.

## EXECUTION BOUNDARY

Closed shared-tree race. Not full runner-compromise immunity. Narrow private-path residual remains.

## POST-FIX RACE

0/60 wins.

## MUTATION TABLE

CONTROL + M-TOCTOU-01..12 + updated C/L: PASS (26/26).

## PRESERVATION / PACKAGE IDENTITY / NODE MATRIX

Ops 92/92 both node lines; package 221/221 both; correspondence 86/0 both. Retained Raven artifact identity + governed npm pins unchanged. packages/release trees unchanged.

## WORKFLOW IMPACT

None.

## RESIDUALS

1. Private gexec same-UID race (narrow).
2. Mode/empty-dir metadata.
3. Node not hash-pinned.

## EXACT FROZEN HANDOFF

```
repo: billybotticelli4u-collab/raven-receipt-verifier
branch: billy/publication-control-v6-toctou-seal
CODE HEAD: 57d018cf944fed39070126ae977a1e294bef76b5
CODE TREE: 74907277b5ed210c4586e522f865646403adb0f5
base: 1e55965e / 0006d5e5
changed (CODE): ops/governed-npm.mjs, ops/governed-npm.test.mjs, ops/publish-exact-release.mjs
authoring: YES; self-GO: NO; publish/merge/deploy: NO
```

## Ready-to-paste independent review prompt

```
Independent adversarial review — PUBLICATION-CONTROL v6 seal
Review only. No merge/publish/deploy/credentials/platform change.
Re-fetch origin before verdict.
repo billybotticelli4u-collab/raven-receipt-verifier
branch billy/publication-control-v6-toctou-seal
CODE HEAD 57d018cf944fed39070126ae977a1e294bef76b5
CODE TREE 74907277b5ed210c4586e522f865646403adb0f5
base 1e55965e / 0006d5e5
Verify CODE diff is exactly three ops files; packages/release/workflow unchanged.
Confirm shared-tree race closed (0 wins); sealed mutate RED; original-after-seal GREEN.
Preserve v5 controls. Matrix Node 22.18.0 and 24.x + governed npm 11.18.0.
Do not claim full runner-compromise immunity. Return CODE GO/NO-GO with residuals.
```
