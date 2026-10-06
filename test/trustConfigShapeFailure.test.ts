// Trust axis on the receipt-SHAPE early-return paths.
//
// `VerifyReceiptOptions` documents that every verification result reports the
// trust axis. That promise is not conditional on the receipt being well-formed.
//
// Both early returns in verifyReceiptV1 — the entry guard
// (`shape_not_an_object`) and the shape check — used to return before the
// trust axis was resolved, so a caller who supplied a full trust policy got NO
// `keyTrusted` and no trust reason at all. This is the same defect the ACP
// verifier fixed in #90; the kernel had diverged and kept it.
//
// Contract preserved here (owner decision): `valid` stays integrity-only. Trust
// is NON-FATAL and additive — it never gates `valid`, and the trust reason is
// appended AFTER the unchanged shape reasons.

import assert from "node:assert/strict";
import test from "node:test";

import { verifyReceiptV1 } from "../src/index.ts";

const KEY = "MCowBQYDK2VwAyEA0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";
const has = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

// Entry guard (shape_not_an_object) and shape-check paths.
const ENTRY: Array<[string, unknown]> = [
  ["non-object receipt", 42],
  ["null receipt", null],
  ["array receipt", []],
];
const SHAPED: Array<[string, unknown]> = [
  ["shape-invalid object, no signer", { notAReceipt: true }],
  ["shape-invalid object with a signerPublicKey", { signerPublicKey: KEY }],
];

for (const [label, receipt] of [...ENTRY, ...SHAPED]) {
  test(`${label}: trustedKeys supplied -> keyTrusted is reported`, () => {
    const res = verifyReceiptV1(receipt, { trustedKeys: [KEY] });
    assert.ok(has(res, "keyTrusted"), "keyTrusted must be present when trustedKeys was supplied");
    assert.equal(typeof res.keyTrusted, "boolean");
    assert.equal(res.valid, false, "valid stays integrity-only");
  });

  test(`${label}: allowUntrustedKey true -> key_trust_not_evaluated`, () => {
    const res = verifyReceiptV1(receipt, { allowUntrustedKey: true });
    assert.ok(has(res, "keyTrusted"), "keyTrusted must be present when allowUntrustedKey was supplied");
    assert.equal(res.keyTrusted, false);
    assert.ok(res.reasons.includes("key_trust_not_evaluated"), JSON.stringify(res.reasons));
  });

  test(`${label}: allowUntrustedKey false without keys -> trust_config_invalid`, () => {
    const res = verifyReceiptV1(receipt, { allowUntrustedKey: false });
    assert.equal(res.keyTrusted, false);
    assert.ok(res.reasons.includes("trust_config_invalid"), JSON.stringify(res.reasons));
  });

  test(`${label}: malformed trustedKeys -> trust_config_invalid, contained`, () => {
    for (const bad of [42, "abc", {}, [KEY, 7]]) {
      const res = verifyReceiptV1(receipt, { trustedKeys: bad as never });
      assert.equal(res.keyTrusted, false);
      assert.ok(res.reasons.includes("trust_config_invalid"), JSON.stringify(res.reasons));
    }
  });
}

test("a shape-failed receipt with NO signerPublicKey can never be trusted", () => {
  // A caller-supplied set must not be able to match a placeholder and make a
  // receipt that carries no signer look trusted.
  const res = verifyReceiptV1({ notAReceipt: true }, { trustedKeys: [""] });
  assert.equal(res.keyTrusted, false, "empty-string key must not match a missing signer");
  assert.ok(res.reasons.includes("trust_config_invalid"), JSON.stringify(res.reasons));
});

test("a shape-failed receipt WITH a matching signerPublicKey resolves trusted", () => {
  const res = verifyReceiptV1({ signerPublicKey: KEY }, { trustedKeys: [KEY] });
  assert.equal(res.keyTrusted, true);
  assert.equal(res.valid, false, "trust never gates valid");
  assert.ok(!res.reasons.includes("key_untrusted"));
});

test("a non-matching signerPublicKey appends key_untrusted after the shape reasons", () => {
  const res = verifyReceiptV1({ signerPublicKey: KEY }, {
    trustedKeys: ["MCowBQYDK2VwAyEAjYvhv+z9XAFfQdKny5PLTGByQMwtc20fyDjhsHknL3s="],
  });
  assert.equal(res.keyTrusted, false);
  assert.equal(res.reasons.at(-1), "key_untrusted", "trust reason is appended last");
  assert.ok(res.reasons.length > 1, "shape reasons are preserved ahead of it");
});

test("hostile receipts resolve trust without escaping an exception", () => {
  const throwing = { get signerPublicKey(): string { throw new TypeError("hostile getter"); } };
  const { proxy, revoke } = Proxy.revocable({}, {});
  revoke();
  for (const receipt of [throwing, proxy]) {
    const res = verifyReceiptV1(receipt, { trustedKeys: [KEY] });
    assert.equal(res.keyTrusted, false);
    assert.equal(res.valid, false);
  }
});

test("NO policy supplied on shape failures fails closed on the trust axis", () => {
  // Shape failures are early returns, so this pins the no-omission invariant on
  // the path most likely to drop trust evaluation.
  for (const [, receipt] of [...ENTRY, ...SHAPED]) {
    const res = verifyReceiptV1(receipt, {});
    assert.equal(has(res, "keyTrusted"), true, "keyTrusted must be present with omitted policy");
    assert.equal(res.keyTrusted, false);
    assert.equal(res.reasons.at(-1), "trust_config_missing");
  }
});
