// Conformance tests for raven-receipt-verifier.
//
// Runs the vendored golden vectors — the SAME fixtures the in-app verifier is tested
// against (apps/launchguard-acp/src/tests/receipt-v1.test.ts) — so this extracted
// kernel cannot silently diverge from production. All tests run OFFLINE.

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  verifyReceiptV1,
  evaluateReceiptRules,
  classifyFindingCodesOutcome,
  canonicalJson,
  RECEIPT_V1_DISCLAIMER,
} from "../src/index.ts";

const { validateHolderAdmission: validateSharedHolderAdmission } = createRequire(import.meta.url)(
  "../../../apps/raven-solana-holders/holderAdmission.js",
) as {
  validateHolderAdmission(input: Record<string, unknown>): { reasons: string[] };
};
const { classifyFindingEnvelopeOutcome: classifyCanonicalOutcome } = createRequire(import.meta.url)(
  "../../../apps/raven-solana-outcome/outcomeRules.js",
) as {
  classifyFindingEnvelopeOutcome(input: Record<string, unknown>): {
    ok: boolean;
    value?: Record<string, unknown>;
  };
};

const FIXTURE_DIR = fileURLToPath(new URL("../fixtures/receipt-v1/", import.meta.url));

const readVector = (name: string): Record<string, unknown> =>
  JSON.parse(fs.readFileSync(FIXTURE_DIR + name + ".json", "utf8")) as Record<string, unknown>;

const OUTCOME_VECTORS = JSON.parse(fs.readFileSync(
  fileURLToPath(new URL("../fixtures/holder-outcome-v1.json", import.meta.url)),
  "utf8",
)) as {
  vectors: Array<{
    name: string;
    findingCodes: string[];
    expected: Record<string, unknown>;
  }>;
  malformedVectors: Array<{
    name: string;
    findingCodes: unknown;
    expectedErrorCode: string;
  }>;
};

// Single-input vectors: assert the shared `expected` shape.
const SINGLE_INPUT_VECTORS = [
  "valid-minimal",
  "valid-with-findings",
  "valid-stale",
  "tampered-finding",
  "tampered-disclaimer",
  "forbidden-word",
  "wrong-domain",
  "wrong-key",
  "unparseable-timestamp",
  "rules-1.1.3-no-holder-historical",
  "rules-1.1.4-state-a-valid",
  "rules-1.1.4-state-b-valid",
  "rules-1.1.4-state-c-valid",
  "rules-1.1.4-acp-bypass-invalid",
  "rules-future-unsupported",
  "rules-version-malformed",
  "rules-1.1.2-no-holder-historical",
  "rules-1.1.3-production-shaped-historical",
  "rules-1.1.4-missing-provenance-invalid",
  "rules-1.1.4-empty-coverage-invalid",
  "rules-1.1.4-observed-unresolved-contradiction",
  "rules-1.1.4-slot-mismatch-invalid",
  "rules-1.1.4-malformed-reason-invalid",
  "rules-1.1.4-missing-attempt-field-invalid",
  "rules-1.1.4-mutated-signed-provenance",
  "rules-1.1.4-attempt-type-invalid",
  "rules-1.1.4-duplicate-unresolved-compound-invalid",
  "rules-1.1.4-attempt-state-type-invalid",
  "rules-1.1.4-primary-adjustment-contradiction-invalid",
  "rules-1.1.3-holder-bearing-derived-compatibility",
];

const REQUIRED_SURFACE_EXPECTATIONS = [
  "producer",
  "acpAdmission",
  "replay",
  "archival",
  "receiptProduction",
  "acpVerifier",
  "verifyJs",
  "pythonVerifier",
  "browserVerifier",
  "freshness",
  "keyTrust",
  "supportStatus",
] as const;

test("all vendored fixture files are present", () => {
  const required = [...SINGLE_INPUT_VECTORS, "canonical-ordering", "production-receipt-v1-bonk-verified"];
  for (const name of required) {
    assert.ok(fs.existsSync(FIXTURE_DIR + name + ".json"), `missing fixture: ${name}.json`);
  }
});

test("1.1.4 outcome vectors match the canonical engine precedence exactly", () => {
  for (const vector of OUTCOME_VECTORS.vectors) {
    const projected = classifyFindingCodesOutcome(vector.findingCodes);
    assert.deepEqual(projected, { ok: true, value: vector.expected }, vector.name);
    const canonical = classifyCanonicalOutcome({
      findings: vector.findingCodes.map((code) => ({ code })),
    });
    assert.deepEqual(canonical, { ok: true, value: vector.expected }, vector.name);
  }
  for (const vector of OUTCOME_VECTORS.malformedVectors) {
    assert.deepEqual(
      classifyFindingCodesOutcome(vector.findingCodes),
      { ok: false, errorCode: vector.expectedErrorCode },
      vector.name,
    );
  }
});

for (const name of SINGLE_INPUT_VECTORS) {
  test(`vector ${name} verifies as expected`, () => {
    const v = readVector(name);
    const expected = v.expected as Record<string, unknown>;
    const trustedKeys = Array.isArray(v.trustedKeys)
      ? new Set(v.trustedKeys as string[])
      : undefined;
    const r = verifyReceiptV1(v.input, { now: v.now as string, trustedKeys });

    assert.equal(r.valid, expected.valid, `valid for ${name}: ${JSON.stringify(r.reasons)}`);
    assert.equal(r.stale, expected.stale, `stale for ${name}`);
    if ("rulesVersion" in expected) assert.equal(r.rulesVersion, expected.rulesVersion);
    if ("rulesStatus" in expected) assert.equal(r.rulesStatus, expected.rulesStatus);
    if (Array.isArray(expected.rulesReasons)) {
      assert.deepEqual(r.rulesReasons, expected.rulesReasons, `rulesReasons for ${name}`);
    }
    if (Array.isArray(expected.rulesReasonsInclude)) {
      for (const reason of expected.rulesReasonsInclude as string[]) {
        assert.ok(
          r.rulesReasons.includes(reason),
          `${name} rulesReasons should include ${reason}: got ${JSON.stringify(r.rulesReasons)}`,
        );
      }
    }
    if ("keyTrusted" in expected) assert.equal(r.keyTrusted, expected.keyTrusted);
    if (Array.isArray(expected.reasonsInclude)) {
      for (const reason of expected.reasonsInclude as string[]) {
        assert.ok(
          r.reasons.includes(reason),
          `${name} reasons should include ${reason}: got ${JSON.stringify(r.reasons)}`,
        );
      }
    }
  });
}

test("every rules fixture defines the complete cross-surface outcome contract", () => {
  for (const name of SINGLE_INPUT_VECTORS.filter((candidate) => candidate.startsWith("rules-"))) {
    const v = readVector(name);
    const expected = v.expected as Record<string, unknown>;
    const surfaces = v.expectedSurfaces as Record<string, unknown>;

    assert.ok(Array.isArray(v.trustedKeys), `${name} must define its trusted-key profile`);
    assert.equal(expected.keyTrusted, true, `${name} must exercise trusted-key acceptance`);
    assert.ok(surfaces && typeof surfaces === "object", `${name} expectedSurfaces missing`);
    assert.deepEqual(
      Object.keys(surfaces).sort(),
      [...REQUIRED_SURFACE_EXPECTATIONS].sort(),
      `${name} cross-surface keys`,
    );
    for (const field of [
      "producer",
      "acpAdmission",
      "replay",
      "archival",
      "receiptProduction",
    ] as const) {
      assert.equal(typeof surfaces[field], "string", `${name} ${field} outcome`);
      assert.notEqual(surfaces[field], "", `${name} ${field} outcome`);
    }

    const verifierOutcome = expected.valid === false
      ? "integrity_invalid"
      : expected.rulesStatus;
    for (const field of [
      "acpVerifier",
      "verifyJs",
      "pythonVerifier",
      "browserVerifier",
    ] as const) {
      assert.equal(surfaces[field], verifierOutcome, `${name} ${field} outcome`);
    }
    assert.equal(surfaces.freshness, expected.stale === true ? "stale" : "fresh", name);
    assert.equal(surfaces.keyTrust, "trusted", name);
    assert.equal(surfaces.supportStatus, expected.rulesStatus, name);
  }
});

test("1.1.4 verifier reasons equal shared admission across bounded compound mutations", () => {
  type MutableReceipt = Record<string, any>;
  const stateB = structuredClone(readVector("rules-1.1.4-state-b-valid").input) as MutableReceipt;
  const stateC = structuredClone(readVector("rules-1.1.4-state-c-valid").input) as MutableReceipt;
  const cases: Array<[string, MutableReceipt, (receipt: MutableReceipt) => void]> = [
    ["duplicate State-B primary", stateB, (receipt) => {
      receipt.findings.push(structuredClone(receipt.findings[0]));
    }],
    ["later copied attempt has non-string commitment", stateB, (receipt) => {
      receipt.findings.push(structuredClone(receipt.findings[0]));
      receipt.findings[1].evidence.holderAttempt.commitment = [];
    }],
    ["later copied attempt has non-string state", stateB, (receipt) => {
      receipt.findings.push(structuredClone(receipt.findings[0]));
      receipt.findings[1].evidence.holderAttempt.state = [];
    }],
    ["all State-C attempt states are non-string", stateC, (receipt) => {
      for (const finding of receipt.findings) finding.evidence.holderAttempt.state = [];
    }],
    ["all State-C commitments are non-string", stateC, (receipt) => {
      for (const finding of receipt.findings) finding.evidence.holderAttempt.commitment = [];
    }],
    ["all State-C reasons are non-string", stateC, (receipt) => {
      for (const finding of receipt.findings) finding.evidence.holderAttempt.reason = [];
    }],
    ["State-C contexts are null", stateC, (receipt) => {
      for (const finding of receipt.findings) finding.evidence.holderAttempt.observation.contexts = null;
    }],
    ["State-C contexts are arrays", stateC, (receipt) => {
      for (const finding of receipt.findings) finding.evidence.holderAttempt.observation.contexts = [];
    }],
    ["State-C contexts are missing", stateC, (receipt) => {
      for (const finding of receipt.findings) delete finding.evidence.holderAttempt.observation.contexts;
    }],
    ["later copied attempt has malformed observation slot", stateC, (receipt) => {
      receipt.findings[1].evidence.holderAttempt.observation.slot = [];
    }],
    ["later copied attempt is missing commitment", stateC, (receipt) => {
      delete receipt.findings[1].evidence.holderAttempt.commitment;
    }],
    ["primary adjustment contradicts qualifier and context", stateC, (receipt) => {
      receipt.findings[0].evidence.adjustedForKnownVenues = true;
    }],
    ["unrelated code cannot manufacture metadata load-bearing context", stateC, (receipt) => {
      receipt.findings.push({
        code: "unrelated.fake",
        source: "mint_account_evidence",
        subject: "metadata_mutability",
        evidence: {},
      });
    }],
  ];

  for (const [name, template, mutate] of cases) {
    const receipt = structuredClone(template);
    mutate(receipt);
    const shared = validateSharedHolderAdmission({
      rulesVersion: receipt.rulesVersion,
      mintAddress: receipt.mintAddress,
      observedSlot: receipt.slot,
      metadataEvaluated: receipt.scopeChecksPerformed.includes("metadata_mutability"),
      findings: receipt.findings,
      coverageGaps: receipt.coverageGaps,
      scopeChecksPerformed: receipt.scopeChecksPerformed,
      scopeChecksNotPerformed: receipt.scopeChecksNotPerformed,
      mode: { mode: "offline" },
    });
    const verifier = evaluateReceiptRules(receipt, true);
    assert.deepEqual(verifier.rulesReasons, shared.reasons, name);
  }

  const duplicate = structuredClone(stateB);
  duplicate.findings.push(structuredClone(duplicate.findings[0]));
  assert.deepEqual(evaluateReceiptRules(duplicate, true).rulesReasons, [
    "holder_primary_cardinality_invalid",
    "holder_state_contradiction",
  ]);
});

test("1.1.4 classifier metrics fail closed with one stable evidence reason", () => {
  type MutableReceipt = Record<string, any>;
  const stateB = readVector("rules-1.1.4-state-b-valid").input as MutableReceipt;
  const stateC = readVector("rules-1.1.4-state-c-valid").input as MutableReceipt;
  const coherentUnavailable = (
    reason: string,
    metrics: Record<string, unknown>,
  ): MutableReceipt => {
    const receipt = structuredClone(stateB);
    const evidence = receipt.findings[0].evidence;
    evidence.reason = reason;
    evidence.metrics = metrics;
    evidence.holderAttempt.reason = reason;
    evidence.holderAttempt.attemptedChecks = ["largest_accounts", "token_supply"];
    evidence.holderAttempt.observation = {
      slot: receipt.slot,
      contexts: {
        mint: true,
        metadata: false,
        largestAccounts: true,
        supply: true,
        venueCustody: false,
        liquidity: false,
      },
    };
    return receipt;
  };

  const cases: Array<[string, MutableReceipt]> = [];
  const highWithZero = structuredClone(stateC);
  highWithZero.findings[0].code = "holders.concentration_high";
  highWithZero.findings[0].evidence.classification = "high_concentration";
  highWithZero.findings[0].evidence.reason = "top1_share_at_or_above_threshold";
  Object.assign(highWithZero.findings[0].evidence.metrics, {
    top1Bps: 0,
    top5Bps: 0,
    top10Bps: 0,
    top1AmountRaw: "0",
    top5AmountRaw: "0",
    top10AmountRaw: "0",
  });
  cases.push(["high classification with zero holder metrics", highWithZero]);
  cases.push([
    "zero-total reason with nonzero supply",
    coherentUnavailable("zero_total_supply", { basis: "total_supply", supplyRaw: "1" }),
  ]);
  cases.push([
    "no-holder reason with zero supply",
    coherentUnavailable("no_holder_accounts_returned", { basis: "total_supply", supplyRaw: "0" }),
  ]);
  const bpsMismatch = structuredClone(stateC);
  bpsMismatch.findings[0].evidence.metrics.top1Bps -= 1;
  cases.push(["basis points disagree with raw amounts", bpsMismatch]);

  for (const [name, receipt] of cases) {
    const expected = ["holder_finding_evidence_invalid"];
    assert.deepEqual(
      evaluateReceiptRules(receipt, true).rulesReasons,
      expected,
      name,
    );
    const shared = validateSharedHolderAdmission({
      rulesVersion: receipt.rulesVersion,
      mintAddress: receipt.mintAddress,
      observedSlot: receipt.slot,
      metadataEvaluated: receipt.scopeChecksPerformed.includes("metadata_mutability"),
      findings: receipt.findings,
      coverageGaps: receipt.coverageGaps,
      scopeChecksPerformed: receipt.scopeChecksPerformed,
      scopeChecksNotPerformed: receipt.scopeChecksNotPerformed,
      mode: { mode: "offline" },
    });
    assert.deepEqual(shared.reasons, expected, `${name}: shared admission`);
  }
});

test("1.1.4 classifier metric precedence is deterministic at every threshold", () => {
  type MutableReceipt = Record<string, any>;
  const stateC = readVector("rules-1.1.4-state-c-valid").input as MutableReceipt;
  const cases = [
    ["holders.concentration_high", "high_concentration", "top1_share_at_or_above_threshold", 3000, 4000, 4500],
    ["holders.concentration_high", "high_concentration", "top5_share_at_or_above_threshold", 2000, 5000, 5500],
    ["holders.concentration_high", "high_concentration", "top10_share_at_or_above_threshold", 2000, 4500, 6000],
    ["holders.concentration_moderate", "moderate_concentration", "top10_share_moderate", 1000, 2000, 3000],
  ] as const;
  for (const [code, classification, reason, top1Bps, top5Bps, top10Bps] of cases) {
    const receipt = structuredClone(stateC);
    const primary = receipt.findings[0];
    primary.code = code;
    primary.evidence.classification = classification;
    primary.evidence.reason = reason;
    Object.assign(primary.evidence.metrics, {
      accountsConsidered: 6,
      top1Bps,
      top5Bps,
      top10Bps,
      top1AmountRaw: String(top1Bps * 100),
      top5AmountRaw: String(top5Bps * 100),
      top10AmountRaw: String(top10Bps * 100),
    });
    assert.deepEqual(evaluateReceiptRules(receipt, true).rulesReasons, [], reason);
  }
});

test("vector canonical-ordering: byte-different inputs share one payloadHash and both verify", () => {
  const v = readVector("canonical-ordering");
  const a = v.inputA as Record<string, unknown>;
  const b = v.inputB as Record<string, unknown>;
  assert.notEqual(JSON.stringify(a), JSON.stringify(b)); // genuinely byte-different
  assert.equal(canonicalJson(a), canonicalJson(b)); // identical canonical form
  assert.equal(a.payloadHash, b.payloadHash); // identical payload hash
  assert.equal(verifyReceiptV1(a, { now: v.now as string }).valid, true);
  assert.equal(verifyReceiptV1(b, { now: v.now as string }).valid, true);
});

test("integrity failure suppresses semantic verdict for an extractable rules version", () => {
  const v = readVector("rules-1.1.4-state-c-valid");
  const tampered = { ...(v.input as Record<string, unknown>), signature: "not-a-signature" };
  const r = verifyReceiptV1(tampered, { now: v.now as string });
  assert.equal(r.valid, false);
  assert.equal(r.rulesVersion, "raven-rules@1.1.4");
  assert.equal(r.rulesStatus, null);
  assert.deepEqual(r.rulesReasons, []);
});

test("missing or non-string rulesVersion is structurally invalid and semantically malformed", () => {
  const v = readVector("rules-1.1.4-state-a-valid");
  for (const input of [
    Object.fromEntries(Object.entries(v.input as Record<string, unknown>).filter(([k]) => k !== "rulesVersion")),
    { ...(v.input as Record<string, unknown>), rulesVersion: 114 },
  ]) {
    const r = verifyReceiptV1(input, { now: v.now as string });
    assert.equal(r.valid, false);
    assert.equal(r.rulesVersion, null);
    assert.equal(r.rulesStatus, "malformed");
    assert.deepEqual(r.rulesReasons, ["malformed_rules_version"]);
  }
});

test("production BONK vector verifies valid + trusted, and payloadHash matches", () => {
  const v = readVector("production-receipt-v1-bonk-verified");
  const trustedKeys = new Set(v.trustedKeys as string[]);
  const r = verifyReceiptV1(v.input, { now: v.now as string, trustedKeys });
  assert.equal(r.valid, true, `reasons: ${JSON.stringify(r.reasons)}`);
  assert.equal(r.keyTrusted, true);
  assert.equal(r.stale, false);
  // The kernel matches PRODUCTION, not just the spec: recompute the payload hash.
  const input = v.input as Record<string, unknown>;
  const body: Record<string, unknown> = {};
  for (const k of [
    "chain", "mintAddress", "tokenProgramAddress", "slot", "timestamp",
    "rulesVersion", "findingTaxonomyVersion", "scopeChecksPerformed",
    "scopeChecksNotPerformed", "coverageGaps", "findings", "interpretations",
    "maxAgeSeconds", "disclaimer",
  ]) body[k] = input[k];
  const recomputed = "sha256:" + createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
  assert.equal(recomputed, input.payloadHash, "recomputed payloadHash must equal the receipt's");
});

test("disclaimer is byte-exact: a one-character change fails verification", () => {
  const v = readVector("valid-minimal");
  const input = v.input as Record<string, unknown>;
  const tampered = { ...input, disclaimer: RECEIPT_V1_DISCLAIMER.slice(0, -1) + "!" };
  const r = verifyReceiptV1(tampered, { now: v.now as string });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("disclaimer_mismatch"), JSON.stringify(r.reasons));
  assert.ok(r.reasons.includes("payload_hash_mismatch"), JSON.stringify(r.reasons));
});

test("hostile deep nesting is contained: an outcome, never an exception (issue #13 item 3)", () => {
  // findings[].evidence nested deep enough to exhaust the recursive
  // canonicalization / string-collection walks on any mainstream engine.
  let evidence: Record<string, unknown> = { leaf: true };
  for (let i = 0; i < 200_000; i++) evidence = { deeper: evidence };
  const v = readVector("valid-minimal");
  const input = {
    ...(v.input as Record<string, unknown>),
    findings: [{ code: "venue.infrastructure_tier_immutable", source: "hostile", evidence }],
  };
  // Must RETURN (fail-closed), never throw.
  const r = verifyReceiptV1(input, { now: v.now as string });
  assert.equal(r.valid, false);
  assert.ok(
    r.reasons.includes("canonicalization_failed") || r.reasons.includes("payload_hash_mismatch"),
    JSON.stringify(r.reasons),
  );
});

test("verification path imports no HTTP/network client (zero-network guard)", () => {
  // The whole point of local verification is that it never calls home. Assert the
  // source of the verify path references no network module.
  const srcDir = fileURLToPath(new URL("../src/", import.meta.url));
  const forbidden = ["node:http", "node:https", "node:net", "node:dgram", "fetch(", "undici", "axios"];
  for (const file of [
    "canonicalJson.ts",
    "receiptRules.ts",
    "receiptV1.ts",
    "verifyReceiptV1.ts",
    "index.ts",
  ]) {
    const src = fs.readFileSync(srcDir + file, "utf8");
    for (const needle of forbidden) {
      assert.ok(!src.includes(needle), `${file} must not reference ${needle}`);
    }
  }
});
