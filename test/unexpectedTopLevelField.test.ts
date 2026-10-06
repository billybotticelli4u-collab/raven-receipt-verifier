import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyReceiptV1 } from "../src/index.ts";

const vector = JSON.parse(readFileSync(
  new URL("../fixtures/receipt-v1/production-receipt-v1-bonk-verified.json", import.meta.url),
  "utf8",
));
const options = { now: vector.now, trustedKeys: [vector.input.signerPublicKey] };

test("Solana verifier rejects an extra top-level field without payload tampering", async () => {
  const control = await verifyReceiptV1(structuredClone(vector.input), options);
  assert.equal(control.valid, true, "genuine baseline must verify");
  const altered = { ...structuredClone(vector.input), unexpected: "attacker" };
  const result = await verifyReceiptV1(altered, options);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.some((reason) => reason.startsWith("shape_unexpected_field")));
});
