import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyReceiptV1 } from "../src/index.ts";

const vector = JSON.parse(readFileSync(
  new URL("../fixtures/receipt-v1/production-receipt-v1-bonk-verified.json", import.meta.url),
  "utf8",
));
const options = { now: vector.now, trustedKeys: [vector.input.signerPublicKey] };

test("Solana receiptId-only tampering is rejected by the shipped verifier", async () => {
  const control = await verifyReceiptV1(structuredClone(vector.input), options);
  assert.equal(control.valid, true, "genuine baseline must verify");
  assert.equal(control.keyTrusted, true, "baseline must use the genuine pin");
  const altered = { ...structuredClone(vector.input), receiptId: "raven-receipt-v1:sha256:" + "0".repeat(64) };
  assert.notEqual(altered.receiptId, vector.input.receiptId);
  const result = await verifyReceiptV1(altered, options);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.includes("receipt_id_mismatch"));
});
