// Frozen public export surface of raven-receipt-verifier@0.1.0.
//
// Raven's active product contract is Solana receipt-v1. The source tree also
// carries receipt-evm-v1 and key-manifest modules whose own comments label
// them PROPOSED — no production EVM signer or manifest exists. Those APIs live
// in src/proposed.ts for internal conformance and must NOT be reachable from
// the package's public export map: publishing them would turn draft work into
// an accidental compatibility commitment. This test pins both directions.

import assert from "node:assert/strict";
import test from "node:test";

import * as publicApi from "../src/index.ts";

const WITHHELD = [
  "verifyReceiptEvmV1",
  "RECEIPT_EVM_DOMAIN",
  "RECEIPT_EVM_VERSION",
  "RECEIPT_EVM_ID_PREFIX",
  "RECEIPT_EVM_DISCLAIMER",
  "computeManifestHash",
  "manifestSigningBytes",
  "signKeyManifest",
  "verifyManifestChain",
  "extractTrustedKeys",
  "KEY_MANIFEST_DOMAIN",
  "KEY_MANIFEST_VERSION",
];

const FROZEN_PUBLIC = [
  "canonicalJson",
  "canonicalJsonStringify",
  "CanonicalJsonError",
  "verifyReceiptV1",
  "verifyReceiptV1ForSubject",
  "evaluateReceiptRules",
  "RAVEN_PRODUCTION_TRUST_ANCHOR",
  "ravenProductionTrustedKeys",
  "classifyFindingCodesOutcome",
  "detectReceiptNamespace",
  "RECEIPT_DOMAIN",
  "RECEIPT_VERSION",
  "RECEIPT_ID_PREFIX",
  "RECEIPT_DISCLAIMER",
  "RECEIPT_V1_DISCLAIMER",
  "FORBIDDEN_WORDS",
  "RECEIPT_BODY_FIELDS",
  "RECEIPT_FIELDS",
  "collectStrings",
  "findForbiddenWords",
];

test("PROPOSED EVM and key-manifest APIs are withheld from the public surface", () => {
  for (const name of WITHHELD) {
    assert.equal(
      name in publicApi,
      false,
      `${name} is PROPOSED and must not be publicly exported`,
    );
  }
});

test("the frozen Solana receipt-v1 surface is present", () => {
  for (const name of FROZEN_PUBLIC) {
    assert.ok(name in publicApi, `${name} missing from the public surface`);
  }
});
