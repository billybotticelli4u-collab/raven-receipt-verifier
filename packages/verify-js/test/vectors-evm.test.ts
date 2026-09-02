// Conformance tests for receipt-evm-v1 (raven-receipt-evm / v1) — the PROPOSED
// EVM sibling namespace. Vectors are TEST-KEY signed (no production key signs
// this namespace); the valid-usdc vector's body is derived from REAL recorded
// Base mainnet evidence. All tests run OFFLINE.

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { canonicalJson, verifyReceiptV1 } from "../src/index.ts";
import { verifyReceiptEvmV1 } from "../src/proposed.ts";

const FIXTURE_DIR = fileURLToPath(new URL("../fixtures/receipt-evm-v1/", import.meta.url));
const readVector = (name: string): Record<string, unknown> =>
  JSON.parse(fs.readFileSync(FIXTURE_DIR + name + ".json", "utf8")) as Record<string, unknown>;

const VECTORS = [
  "valid-minimal-evm",
  "valid-usdc-base-testkey",
  "tampered-finding-evm",
  "tampered-disclaimer-evm",
  "forbidden-word-evm",
  "wrong-domain-evm",
  "wrong-key-evm",
  "valid-stale-evm",
  "unparseable-timestamp-evm",
  "d7-rsa-evm",
  "d7-ec-evm",
];

for (const name of VECTORS) {
  test(`evm vector ${name} verifies as expected`, () => {
    const v = readVector(name);
    const expected = v.expected as Record<string, unknown>;
    const trustedKeys = Array.isArray(v.trustedKeys) ? new Set(v.trustedKeys as string[]) : undefined;
    const r = verifyReceiptEvmV1(v.input, { now: v.now as string, trustedKeys });
    assert.equal(r.valid, expected.valid, `valid for ${name}: ${JSON.stringify(r.reasons)}`);
    assert.equal(r.stale, expected.stale, `stale for ${name}`);
    assert.equal("rulesStatus" in r, false, "EVM verifier must not acquire Solana rules fields");
    assert.equal("rulesReasons" in r, false, "EVM verifier must not acquire Solana rules fields");
    if ("keyTrusted" in expected) assert.equal(r.keyTrusted, expected.keyTrusted);
    if (Array.isArray(expected.reasonsInclude)) {
      for (const reason of expected.reasonsInclude as string[]) {
        assert.ok(r.reasons.includes(reason), `${name} needs ${reason}: got ${JSON.stringify(r.reasons)}`);
      }
    }
  });
}

test("evm vector canonical-ordering: byte-different inputs share one payloadHash and both verify", () => {
  const v = readVector("canonical-ordering-evm");
  const a = v.inputA as Record<string, unknown>;
  const b = v.inputB as Record<string, unknown>;
  assert.notEqual(JSON.stringify(a), JSON.stringify(b)); // genuinely byte-different
  assert.equal(canonicalJson(a), canonicalJson(b)); // identical canonical form
  assert.equal(a.payloadHash, b.payloadHash);
  assert.equal(verifyReceiptEvmV1(a, { now: v.now as string }).valid, true);
  assert.equal(verifyReceiptEvmV1(b, { now: v.now as string }).valid, true);
});

test("real-evidence vector carries the observed USDC facts (proxy, owner, selector observations)", () => {
  const v = readVector("valid-usdc-base-testkey");
  const input = v.input as { findings: Array<{ code: string }>; implementationAddress: string };
  const codes = input.findings.map((f) => f.code);
  assert.ok(codes.includes("evm_contract.upgradeable_proxy_zos_legacy"));
  assert.ok(codes.includes("evm_issuer_control.owner_present"));
  assert.ok(codes.includes("evm_issuer_control.mint_selector_present"));
  assert.match(input.implementationAddress, /^0x[0-9a-fA-F]{40}$/);
});

test("cross-namespace separation: an EVM receipt is rejected by the Solana verifier and vice versa", () => {
  const evm = readVector("valid-minimal-evm");
  const solanaVerdict = verifyReceiptV1(evm.input, { now: evm.now as string });
  assert.equal(solanaVerdict.valid, false); // wrong shape entirely
  assert.ok(solanaVerdict.reasons.some((r) => r.startsWith("shape_")));

  const solanaVector = JSON.parse(
    fs.readFileSync(
      fileURLToPath(new URL("../fixtures/receipt-v1/valid-minimal.json", import.meta.url)),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const evmVerdict = verifyReceiptEvmV1(solanaVector.input, { now: solanaVector.now as string });
  assert.equal(evmVerdict.valid, false);
  assert.ok(evmVerdict.reasons.some((r) => r.startsWith("shape_")));
});

test("evm hostile deep nesting is contained: an outcome, never an exception", () => {
  let evidence: Record<string, unknown> = { leaf: true };
  for (let i = 0; i < 200_000; i++) evidence = { deeper: evidence };
  const v = readVector("valid-minimal-evm");
  const input = {
    ...(v.input as Record<string, unknown>),
    findings: [{ code: "evm_contract.code_present", source: "hostile", evidence }],
  };
  const r = verifyReceiptEvmV1(input, { now: v.now as string });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("canonicalization_failed") || r.reasons.includes("payload_hash_mismatch"));
});
