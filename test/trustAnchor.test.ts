// The embedded bytes must be internally consistent and match the signer of a
// committed production receipt. These tests do not establish which key a
// customer intended to trust; that initial selection comes from the
// authenticated package/version/integrity onboarding handoff.
import assert from "node:assert/strict";
import test from "node:test";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  RAVEN_PRODUCTION_TRUST_ANCHOR,
  ravenProductionTrustedKeys,
  verifyReceiptV1,
} from "../src/index.ts";

const anchor = RAVEN_PRODUCTION_TRUST_ANCHOR[0];

test("the anchor is a single canonical Ed25519 key with a derivable keyId", () => {
  assert.equal(RAVEN_PRODUCTION_TRUST_ANCHOR.length, 1, "exactly one production key is anchored");
  const der = Buffer.from(anchor.publicKeyBase64, "base64");
  assert.equal(der.length, 44, "canonical Ed25519 SPKI is 44 bytes");
  assert.ok(der.toString("hex").startsWith("302a300506032b6570032100"), "canonical Ed25519 SPKI prefix");
  assert.equal(der.toString("base64"), anchor.publicKeyBase64, "base64 re-encodes byte-identically (no padding slack)");

  // keyId = rvk_ + first 16 hex of sha256 over the base64 SPKI STRING.
  // Non-vacuous: of the four candidate preimages, exactly this one matches.
  const derived = "rvk_" + createHash("sha256").update(anchor.publicKeyBase64, "ascii").digest("hex").slice(0, 16);
  assert.equal(derived, anchor.keyId, "keyId must derive from the anchored key material");

  assert.equal(createHash("sha256").update(der).digest("hex"), anchor.spkiSha256Hex, "SPKI fingerprint");
  assert.equal(createHash("sha256").update(der.subarray(12)).digest("hex"), anchor.rawKeySha256Hex, "raw-32 fingerprint");
});

test("the anchored key matches the signer of a committed production receipt", () => {
  const receipt = JSON.parse(
    readFileSync(new URL("../fixtures/receipt-v1/production-receipt-v1-bonk-2026-07-03.json", import.meta.url), "utf8"),
  );
  const result = verifyReceiptV1(receipt, {
    now: new Date("2026-07-03T00:06:00.000Z"),
    trustedKeys: ravenProductionTrustedKeys(),
  });
  assert.equal(result.valid, true, "the committed production receipt must verify");
  assert.equal(result.keyTrusted, true, "the committed receipt signer must be in the embedded anchored set");

  // RED capability: a single-character key mutation must break trust.
  const nearMiss = anchor.publicKeyBase64.slice(0, -2) + "x=";
  const wrong = verifyReceiptV1(receipt, {
    now: new Date("2026-07-03T00:06:00.000Z"),
    trustedKeys: new Set([nearMiss]),
  });
  assert.equal(wrong.keyTrusted, false, "a near-miss key (final character flipped) must be untrusted");
  assert.equal(wrong.valid, true, "…while validity, an independent axis, is unaffected");
});

test("ravenProductionTrustedKeys returns a fresh mutable set each call", () => {
  const a = ravenProductionTrustedKeys();
  a.add("customer-added-key");
  assert.equal(ravenProductionTrustedKeys().has("customer-added-key"), false, "callers cannot mutate the anchor");
  assert.equal(ravenProductionTrustedKeys().size, 1);
});
