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
// axis (`trust_config_invalid`), never a silent pass. Omitting both is missing
// trust configuration and fails closed on the trust axis; only
// `allowUntrustedKey: true` is the typed opt-out.

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
const OTHER_ED25519_KEY = "MCowBQYDK2VwAyEAjYvhv+z9XAFfQdKny5PLTGByQMwtc20fyDjhsHknL3s=";
const P256_KEY = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEnIJWUYbtA5PyMJt+xnvSvMNASUHyIpq47I5sUPAMPZzPe9zvMSj9Dkls9/lZYYlFmvK4pOD3dDDryegBERIFcg==";
const RSA_KEY = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy70mNqIv7ffp6oFaHfRwXLdmyMZIXpYhlb8/C3VhkG4RP2GC1vVWkciprOFjNli2vomWXvmMfYvYIYQ7Jx76qu1UPxXapI9kignib4QMDmBo0KQeXwXEGTsOPSaq7YStvsZus2sPJvBucRiIKKfOlc1dLdYomW5sa1tEbJdbDfZDr0x2dwxaGZNg6sFEp684NT28C7fpU2lXnlHKaTFwc6LdNScIupiB7jTHyTsj96AqlkJQtU9omsBZJedUUD9V8PgjGXxwpgiwM/PMj9bS+8mzyu4rvBvbMBueMlrLKigtsciQ0vKleZNkp+kGhtJh3JDEZ5J8DYGjJG1n5kIHiQIDAQAB";
const hasOwn = (value: object, key: string) => Object.prototype.hasOwnProperty.call(value, key);
const derBase64 = (hex: string): string => Buffer.from(hex, "hex").toString("base64");

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

test("receipt-v1 trust accepts only canonical Ed25519 SPKI material", () => {
  const correct = verifyReceiptV1(wrongKey.input, {
    now: wrongKey.now,
    trustedKeys: [wrongKey.input.signerPublicKey],
  });
  assert.equal(correct.valid, true);
  assert.equal(correct.keyTrusted, true);
  assert.deepEqual(correct.reasons, []);

  const wrongEd25519 = verifyReceiptV1(wrongKey.input, {
    now: wrongKey.now,
    trustedKeys: [OTHER_ED25519_KEY],
  });
  assert.equal(wrongEd25519.valid, true);
  assert.equal(wrongEd25519.keyTrusted, false);
  assert.deepEqual(wrongEd25519.reasons, ["key_untrusted"]);

  for (const [label, key] of [
    ["P-256", P256_KEY],
    ["RSA", RSA_KEY],
    ["syntactically valid unknown SPKI", derBase64("3009300306012a03020001")],
    ["syntactically valid SPKI with parameters", derBase64("300b300506012a050003020001")],
    ["syntactically valid padded SPKI bit string", derBase64("3009300306012a03020204")],
  ]) {
    const result = verifyReceiptV1(wrongKey.input, { now: wrongKey.now, trustedKeys: [key] });
    assert.equal(result.valid, true, label);
    assert.equal(result.keyTrusted, false, label);
    assert.deepEqual(result.reasons, ["trust_key_type_unsupported"], label);
  }
});

test("malformed trust-key encodings remain trust_config_invalid", () => {
  const malformed = [
    ["noncanonical base64", "abc"],
    ["empty DER", ""],
    ["wrong outer tag", derBase64("3100")],
    ["trailing DER data", derBase64("300000")],
    ["truncated outer sequence", derBase64("3003")],
    ["missing algorithm sequence", derBase64("30020300")],
    ["empty algorithm OID", derBase64("300730020600030100")],
    ["non-minimal algorithm OID", derBase64("300a30040602802a03020001")],
    ["unterminated algorithm OID", derBase64("3009300306018003020001")],
    ["indefinite parameter length", derBase64("300b300606012a058000030100")],
    ["extra algorithm parameters", derBase64("300d300706012a0500050003020001")],
    ["missing key bit string", derBase64("3005300306012a")],
    ["empty key bit string", derBase64("3007300306012a0300")],
    ["invalid unused-bit count", derBase64("3009300306012a03020801")],
    ["bit string without key bytes", derBase64("3008300306012a030100")],
    ["nonzero bit-string padding", derBase64("3009300306012a03020205")],
    ["non-minimal long-form length", derBase64("308109300306012a03020001")],
  ] as const;
  for (const [label, key] of malformed) {
    const result = verifyReceiptV1(wrongKey.input, { now: wrongKey.now, trustedKeys: [key] });
    assert.equal(result.valid, true, label);
    assert.equal(result.keyTrusted, false, label);
    assert.deepEqual(result.reasons, ["trust_config_invalid"], label);
  }
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

test("omitting trustedKeys and allowUntrustedKey fails closed on the trust axis", () => {
  const r = verifyReceiptV1(wrongKey.input, { now: wrongKey.now });
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["trust_config_invalid"]);
  assert.equal(r.valid, true);
});

test("empty trustedKeys is valid trust config with no match, not malformed or omitted", () => {
  for (const trustedKeys of [[], new Set<string>()]) {
    const r = verifyReceiptV1(wrongKey.input, { now: wrongKey.now, trustedKeys });
    assert.equal(r.valid, true);
    assert.equal(r.keyTrusted, false);
    assert.deepEqual(r.reasons, ["key_untrusted"]);
  }
});

test("trustedKeys takes precedence when allowUntrustedKey:true is also supplied", () => {
  const trusted = verifyReceiptV1(wrongKey.input, {
    now: wrongKey.now,
    trustedKeys: [wrongKey.input.signerPublicKey],
    allowUntrustedKey: true,
  });
  assert.equal(trusted.valid, true);
  assert.equal(trusted.keyTrusted, true);
  assert.deepEqual(trusted.reasons, []);

  const untrusted = verifyReceiptV1(wrongKey.input, {
    now: wrongKey.now,
    trustedKeys: [GENUINE_KEY],
    allowUntrustedKey: true,
  });
  assert.equal(untrusted.valid, true);
  assert.equal(untrusted.keyTrusted, false);
  assert.deepEqual(untrusted.reasons, ["key_untrusted"]);
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
    trustedKeys: [wrongKey.input.signerPublicKey],
    allowUntrustedKey: "false" as never,
  });
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["trust_config_invalid"]);
  assert.equal(r.valid, true);
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

test("whole options hostility is contained on the trust axis, not receipt shape", () => {
  const { proxy, revoke } = Proxy.revocable<VerifyOptionsProbe>({ now: wrongKey.now }, {});
  revoke();
  const cases: Array<[string, unknown]> = [
    ["null options", null],
    ["revoked options Proxy", proxy],
    [
      "throwing options Proxy",
      new Proxy(
        {},
        {
          get() {
            throw new TypeError("hostile options");
          },
        },
      ),
    ],
  ];

  for (const [label, options] of cases) {
    let r;
    assert.doesNotThrow(() => {
      r = verifyReceiptV1(wrongKey.input, options as never);
    }, label);
    assert.equal(r!.valid, true, label);
    assert.equal(hasOwn(r!, "keyTrusted"), true, label);
    assert.equal(r!.keyTrusted, false, label);
    assert.ok(r!.reasons.includes("trust_config_invalid"), `${label}: ${JSON.stringify(r!.reasons)}`);
    assert.ok(!r!.reasons.some((reason) => reason.startsWith("shape_")), label);
  }
});

test("throwing option getters are contained as malformed trust config", () => {
  const cases: Array<[string, VerifyOptionsProbe]> = [
    [
      "trustedKeys getter",
      {
        now: wrongKey.now,
        get trustedKeys() {
          throw new TypeError("trustedKeys trap");
        },
      },
    ],
    [
      "allowUntrustedKey getter",
      {
        now: wrongKey.now,
        get allowUntrustedKey() {
          throw new TypeError("allowUntrustedKey trap");
        },
      },
    ],
  ];

  for (const [label, options] of cases) {
    const r = verifyReceiptV1(wrongKey.input, options as never);
    assert.equal(r.valid, true, label);
    assert.equal(r.keyTrusted, false, label);
    assert.deepEqual(r.reasons, ["trust_config_invalid"], label);
  }
});

test("stateful trustedKeys getter is read once and cannot flip trust to true", () => {
  let reads = 0;
  const options: VerifyOptionsProbe = {
    now: wrongKey.now,
    get trustedKeys() {
      reads += 1;
      return reads === 1 ? [] : [wrongKey.input.signerPublicKey];
    },
  };

  const r = verifyReceiptV1(wrongKey.input, options as never);
  assert.equal(reads, 1);
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["key_untrusted"]);
});

test("stateful allowUntrustedKey getter without a pin is read once and cannot mutate into opt-out", () => {
  let reads = 0;
  const options: VerifyOptionsProbe = {
    now: wrongKey.now,
    get allowUntrustedKey() {
      reads += 1;
      return reads === 1 ? false : true;
    },
  };

  const r = verifyReceiptV1(wrongKey.input, options as never);
  assert.equal(reads, 1);
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["trust_config_invalid"]);
});

test("stateful allowUntrustedKey getter with empty keys is read once and pin precedence holds", () => {
  let reads = 0;
  const options: VerifyOptionsProbe = {
    now: wrongKey.now,
    trustedKeys: [],
    get allowUntrustedKey() {
      reads += 1;
      return reads === 1 ? false : true;
    },
  };

  const r = verifyReceiptV1(wrongKey.input, options as never);
  assert.equal(reads, 1);
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["key_untrusted"]);
});

test("latent EVM verifier contains whole options and stateful trust getters", () => {
  const wholeNull = verifyReceiptEvmV1(evmValid.input, null as never);
  assert.equal(wholeNull.valid, true);
  assert.equal(wholeNull.keyTrusted, false);
  assert.ok(wholeNull.reasons.includes("trust_config_invalid"));
  assert.ok(!wholeNull.reasons.some((reason) => reason.startsWith("shape_")));

  let reads = 0;
  const statefulPin: VerifyOptionsProbe = {
    now: evmValid.now,
    get trustedKeys() {
      reads += 1;
      return reads === 1 ? [] : evmValid.trustedKeys;
    },
  };
  const r = verifyReceiptEvmV1(evmValid.input, statefulPin as never);
  assert.equal(reads, 1);
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, false);
  assert.deepEqual(r.reasons, ["key_untrusted"]);
});

test("latent EVM shape branches preserve trust-axis evaluation", () => {
  const cases: Array<[string, (receipt: Record<string, unknown>) => void]> = [
    ["token address type", (receipt) => { receipt.tokenAddress = 7; }],
    ["token address format", (receipt) => { receipt.tokenAddress = "0xbad"; }],
    ["implementation address type", (receipt) => { receipt.implementationAddress = 7; }],
    ["implementation address format", (receipt) => { receipt.implementationAddress = "0xbad"; }],
    ["block number", (receipt) => { receipt.blockNumber = 1.5; }],
    ["block hash type", (receipt) => { receipt.blockHash = 7; }],
    ["block hash format", (receipt) => { receipt.blockHash = "0xbad"; }],
  ];
  for (const [label, mutate] of cases) {
    const receipt = structuredClone(evmValid.input) as Record<string, unknown>;
    mutate(receipt);
    const result = verifyReceiptEvmV1(receipt, {
      now: evmValid.now,
      trustedKeys: evmValid.trustedKeys,
    });
    assert.equal(result.valid, false, label);
    assert.equal(result.keyTrusted, true, label);
    assert.ok(result.reasons.some((reason) => reason.startsWith("shape_type:")), label);
  }
});

test("latent EVM receipt-id mismatch is independent from signer trust", () => {
  const receipt = structuredClone(evmValid.input) as Record<string, unknown>;
  receipt.receiptId = "raven-receipt-evm-v1:sha256:" + "0".repeat(64);
  const result = verifyReceiptEvmV1(receipt, {
    now: evmValid.now,
    trustedKeys: evmValid.trustedKeys,
  });
  assert.equal(result.valid, false);
  assert.equal(result.keyTrusted, true);
  assert.deepEqual(result.reasons, ["receipt_id_mismatch"]);
});

interface VerifyOptionsProbe {
  now?: string | Date;
  trustedKeys?: unknown;
  allowUntrustedKey?: unknown;
}
