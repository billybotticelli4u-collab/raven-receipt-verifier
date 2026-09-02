// Trust-input contract tests — fail-closed handling of trustedKeys and the
// explicit allowUntrustedKey escape hatch.
//
// Contract (owner decision, 2026-07-28): `valid` is integrity-only (checks
// 1–5); trust, freshness and rules conformance are separate axes. Every
// malformed trustedKeys value — any non-collection, any non-string member —
// must produce a typed `trust_config_invalid` with trust not established; no
// exception may escape for any input. Trust evaluation is opt-in via
// trustedKeys; the typed opt-out is `allowUntrustedKey: true`; passing
// `allowUntrustedKey: false` without keys is a contract error on the trust
// axis (`trust_config_invalid`), never a silent pass. Omitting both preserves
// the historical not-evaluated behavior (keyTrusted absent).

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { verifyReceiptV1 } from "../src/index.ts";
import { verifyReceiptEvmV1 } from "../src/proposed.ts";

const SOL_FIXTURES = fileURLToPath(new URL("../fixtures/receipt-v1/", import.meta.url));
const EVM_FIXTURES = fileURLToPath(new URL("../fixtures/receipt-evm-v1/", import.meta.url));
const load = (dir: string, name: string) => JSON.parse(fs.readFileSync(dir + name, "utf8"));

const wrongKey = load(SOL_FIXTURES, "wrong-key.json"); // attacker-signed; signature self-consistent (integrity valid)
const tamperedFinding = load(SOL_FIXTURES, "tampered-finding.json"); // integrity INVALID
const evmValid = load(EVM_FIXTURES, "valid-minimal-evm.json");

const GENUINE_KEY = "MCowBQYDK2VwAyEA0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";

const MALFORMED_VALUES: Array<[string, unknown]> = [
  ["number", 42],
  ["null", null],
  ["string", "abc"],
  ["plain object", {}],
  ["mixed array", [GENUINE_KEY, 42, null, {}]],
];

for (const [label, value] of MALFORMED_VALUES) {
  test(`malformed trustedKeys (${label}) fails closed and typed, no exception`, () => {
    let r;
    assert.doesNotThrow(() => {
      r = verifyReceiptV1(wrongKey.input, {
        now: wrongKey.now,
        trustedKeys: value as never,
      });
    });
    assert.equal(r!.keyTrusted, false);
    assert.ok(r!.reasons.includes("trust_config_invalid"), `reasons: ${JSON.stringify(r!.reasons)}`);
    // Axes stay independent: integrity and freshness are unaffected by a broken trust config.
    assert.equal(r!.valid, true);
    assert.equal(r!.stale, false);
  });
}

test("malformed trustedKeys on the EVM verifier fails closed and typed", () => {
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptEvmV1(evmValid.input, { now: evmValid.now, trustedKeys: 42 as never });
  });
  assert.equal(r!.keyTrusted, false);
  assert.ok(r!.reasons.includes("trust_config_invalid"));
  assert.equal(r!.valid, true);
});

test("EVM verifier accepts trustedKeys as a validated string array", () => {
  const r = verifyReceiptEvmV1(evmValid.input, {
    now: evmValid.now,
    trustedKeys: evmValid.trustedKeys, // array, as any JSON-loading caller will hold
  });
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, true);
  assert.deepEqual(r.reasons, []);
});

test("Solana verifier accepts trustedKeys as a validated string array", () => {
  const r = verifyReceiptV1(wrongKey.input, {
    now: wrongKey.now,
    trustedKeys: [GENUINE_KEY],
  });
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["key_untrusted"]);
});

test("allowUntrustedKey: true is the typed opt-out of trust evaluation", () => {
  const r = verifyReceiptV1(wrongKey.input, { now: wrongKey.now, allowUntrustedKey: true });
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["key_trust_not_evaluated"]);
  assert.equal(r.valid, true); // valid stays integrity-only
});

test("allowUntrustedKey: false without keys is a typed trust-config error, never silent", () => {
  const r = verifyReceiptV1(wrongKey.input, { now: wrongKey.now, allowUntrustedKey: false });
  assert.equal(r.keyTrusted, false);
  assert.ok(r.reasons.includes("trust_config_invalid"));
  assert.equal(r.valid, true); // trust failure does not redefine integrity
});

test("allowUntrustedKey: false with valid keys evaluates trust normally", () => {
  const r = verifyReceiptV1(wrongKey.input, {
    now: wrongKey.now,
    trustedKeys: new Set([GENUINE_KEY]),
    allowUntrustedKey: false,
  });
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["key_untrusted"]);
});

test("omitting trustedKeys and allowUntrustedKey preserves historical not-evaluated behavior", () => {
  const r = verifyReceiptV1(wrongKey.input, { now: wrongKey.now });
  assert.equal(r.keyTrusted, undefined);
  assert.deepEqual(r.reasons, []);
  assert.equal(r.valid, true);
});

test("axes independence: broken trust config on an integrity-invalid receipt", () => {
  const r = verifyReceiptV1(tamperedFinding.input, {
    now: tamperedFinding.now,
    trustedKeys: 42 as never,
  });
  assert.equal(r.valid, false); // integrity axis
  assert.equal(r.keyTrusted, false); // trust axis
  assert.ok(r.reasons.includes("payload_hash_mismatch"));
  assert.ok(r.reasons.includes("trust_config_invalid"));
});

// --- Post-merge review hardening (#84 P1/P2) ---
// P1: a non-boolean allowUntrustedKey (realistic for env-derived strings such
// as "false") must be malformed trust configuration — never silently treated
// as omitted, which would drop the trust axis entirely.
// P2: normalization must contain exceptions from hostile collections, so no
// input value can make the verifier throw.

const MALFORMED_ALLOW: Array<[string, unknown]> = [
  ["string 'false' (env-derived)", "false"],
  ["string 'true'", "true"],
  ["null", null],
  ["zero", 0],
  ["plain object", {}],
  ["number one", 1],
];

for (const [label, value] of MALFORMED_ALLOW) {
  test(`malformed allowUntrustedKey (${label}) fails closed and typed, never silently omits trust`, () => {
    let r;
    assert.doesNotThrow(() => {
      r = verifyReceiptV1(wrongKey.input, { now: wrongKey.now, allowUntrustedKey: value as never });
    });
    assert.equal(r!.keyTrusted, false);
    assert.ok(r!.reasons.includes("trust_config_invalid"), `reasons: ${JSON.stringify(r!.reasons)}`);
    assert.equal(r!.valid, true); // trust failure does not redefine integrity
  });
}

test("malformed allowUntrustedKey is invalid even when valid trustedKeys are supplied", () => {
  const r = verifyReceiptV1(wrongKey.input, {
    now: wrongKey.now,
    trustedKeys: [GENUINE_KEY],
    allowUntrustedKey: "false" as never,
  });
  assert.equal(r.keyTrusted, false);
  assert.ok(r.reasons.includes("trust_config_invalid"));
});

test("a Set subclass with a throwing iterator cannot escape normalization", () => {
  class ThrowingSet extends Set<string> {
    override [Symbol.iterator](): SetIterator<string> {
      throw new TypeError("hostile iterator");
    }
  }
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1(wrongKey.input, {
      now: wrongKey.now,
      trustedKeys: new ThrowingSet([GENUINE_KEY]),
    });
  });
  assert.equal(r!.keyTrusted, false);
  assert.ok(r!.reasons.includes("trust_config_invalid"));
  assert.equal(r!.valid, true);
});

test("a revoked Proxy trustedKeys cannot escape normalization", () => {
  const { proxy, revoke } = Proxy.revocable<unknown>([GENUINE_KEY], {});
  revoke();
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1(wrongKey.input, { now: wrongKey.now, trustedKeys: proxy as never });
  });
  assert.equal(r!.keyTrusted, false);
  assert.ok(r!.reasons.includes("trust_config_invalid"));
  assert.equal(r!.valid, true);
});
