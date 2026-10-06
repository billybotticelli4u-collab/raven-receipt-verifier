import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { verifyReceiptV1 } from "../src/index.ts";

const vector = JSON.parse(readFileSync(
  new URL("../fixtures/receipt-v1/production-receipt-v1-bonk-verified.json", import.meta.url),
  "utf8",
));
const options = { now: vector.now, trustedKeys: [vector.input.signerPublicKey] };

test("Solana verifier rejects non-zero base64 pad bits for the genuine signer", async () => {
  const control = await verifyReceiptV1(structuredClone(vector.input), options);
  assert.equal(control.valid, true, "genuine baseline must verify");
  const canonical: string = vector.input.signerPublicKey;
  assert.ok(canonical.endsWith("=") && !canonical.endsWith("=="), "44-byte SPKI padding");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const index = alphabet.indexOf(canonical.at(-2)!);
  assert.ok(index >= 0);
  assert.equal(index & 3, 0, "canonical final sextet must have zero pad bits");
  const alias = canonical.slice(0, -2) + alphabet[index | 1] + "=";
  assert.notEqual(alias, canonical);
  assert.deepEqual(Buffer.from(alias, "base64"), Buffer.from(canonical, "base64"),
    "the attack changes spelling, not key bytes");
  const result = await verifyReceiptV1({ ...structuredClone(vector.input), signerPublicKey: alias }, options);
  assert.equal(result.valid, false, "same decoded bytes must not bypass canonical-SPKI enforcement");
});
