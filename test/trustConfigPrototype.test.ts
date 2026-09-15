// Prototype-chain trust injection (Phase-B blocker 1, 2026-09-05).
//
// LOCKED RULE: only OWN properties supplied by the caller may define trust
// configuration. Inherited properties — Object.prototype pollution or a hostile
// custom prototype — are semantically ABSENT. `options = {}` with
// `Object.prototype.trustedKeys` populated must behave exactly like trustedKeys
// was omitted (keyTrusted:false, trust_config_missing); inherited
// allowUntrustedKey / wholeOptionsInvalid / any normalization field must not
// alter the trust result; prototype getters must never be invoked when the
// property is not own; hostile options must never become receipt-shape errors.

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { verifyReceiptV1, verifyReceiptV1ForSubject } from "../src/index.ts";
import { verifyReceiptEvmV1 } from "../src/proposed.ts";

const SOL = fileURLToPath(new URL("../fixtures/receipt-v1/", import.meta.url));
const EVM = fileURLToPath(new URL("../fixtures/receipt-evm-v1/", import.meta.url));
const load = (dir: string, name: string) => JSON.parse(fs.readFileSync(dir + name, "utf8"));
const genuine = load(SOL, "valid-minimal.json"); // integrity valid, signed by GENUINE
const evmGenuine = load(EVM, "valid-minimal-evm.json");
const GENUINE: string = genuine.input.signerPublicKey;
const OTHER_ED25519 = "MCowBQYDK2VwAyEAjYvhv+z9XAFfQdKny5PLTGByQMwtc20fyDjhsHknL3s=";

const TRUST_CODES = new Set([
  "trust_config_missing",
  "trust_config_invalid",
  "key_untrusted",
  "key_trust_not_evaluated",
  "trust_key_type_unsupported",
]);
const trustReasons = (r: { reasons: string[] }) => r.reasons.filter((x) => TRUST_CODES.has(x));

type Surface = {
  name: string;
  /** The surface fixture's own signer — the correct pin for that surface. */
  pin: string;
  run: (opts: unknown) => { valid: boolean; keyTrusted: boolean; reasons: string[] };
};
const SURFACES: Surface[] = [
  { name: "kernel", pin: GENUINE, run: (o) => verifyReceiptV1(genuine.input, o as never) },
  { name: "evm", pin: evmGenuine.input.signerPublicKey, run: (o) => verifyReceiptEvmV1(evmGenuine.input, o as never) },
  {
    name: "wrapper",
    pin: GENUINE,
    run: (o) => verifyReceiptV1ForSubject(genuine.input, {
      chain: genuine.input.chain,
      mintAddress: genuine.input.mintAddress,
      tokenProgramAddress: genuine.input.tokenProgramAddress,
    }, o as never),
  },
];

/** Pollute Object.prototype for the duration of fn, always restoring it. */
const withObjectPrototype = (props: PropertyDescriptorMap, fn: () => void) => {
  const proto = Object.prototype as Record<string, unknown>;
  for (const key of Object.keys(props)) assert.equal(key in proto, false, `${key} already on Object.prototype`);
  for (const [key, desc] of Object.entries(props)) Object.defineProperty(proto, key, { ...desc, configurable: true });
  try {
    fn();
  } finally {
    for (const key of Object.keys(props)) delete proto[key];
  }
};
const data = (value: unknown): PropertyDescriptor => ({ value, writable: true, enumerable: false });

const expectTrust = (
  label: string,
  r: { valid: boolean; keyTrusted: boolean; reasons: string[] },
  keyTrusted: boolean,
  reasons: string[],
) => {
  assert.equal(r.valid, true, `${label}: valid must stay integrity-only; reasons=${JSON.stringify(r.reasons)}`);
  assert.equal(r.keyTrusted, keyTrusted, `${label}: keyTrusted; reasons=${JSON.stringify(r.reasons)}`);
  assert.deepEqual(trustReasons(r), reasons, `${label}: trust reasons`);
  assert.ok(!r.reasons.some((x) => x.startsWith("shape_")), `${label}: hostile options must never become receipt shape errors: ${JSON.stringify(r.reasons)}`);
};

for (const s of SURFACES) {
  const now = s.name === "evm" ? evmGenuine.now : genuine.now;
  const GENUINE = s.pin;

  test(`P1 [${s.name}] Object.prototype.trustedKeys with options {} is omission (trust_config_missing)`, () => {
    withObjectPrototype({ trustedKeys: data([GENUINE]) }, () => {
      expectTrust("P1", s.run({ now }), false, ["trust_config_missing"]);
    });
  });

  test(`P2 [${s.name}] custom prototype carrying trustedKeys is not trusted`, () => {
    const opts = Object.assign(Object.create({ trustedKeys: [GENUINE] }), { now });
    expectTrust("P2", s.run(opts), false, ["trust_config_missing"]);
  });

  test(`P3 [${s.name}] Object.prototype.allowUntrustedKey=true stays trust_config_missing, not key_trust_not_evaluated`, () => {
    withObjectPrototype({ allowUntrustedKey: data(true) }, () => {
      expectTrust("P3", s.run({ now }), false, ["trust_config_missing"]);
    });
  });

  test(`P4a [${s.name}] custom prototype wholeOptionsInvalid=true cannot poison own valid trustedKeys`, () => {
    const opts = Object.assign(Object.create({ wholeOptionsInvalid: true }), { now, trustedKeys: [GENUINE] });
    expectTrust("P4a", s.run(opts), true, []);
  });

  test(`P4b [${s.name}] Object.prototype.wholeOptionsInvalid=true cannot poison own valid trustedKeys`, () => {
    withObjectPrototype({ wholeOptionsInvalid: data(true) }, () => {
      expectTrust("P4b", s.run({ now, trustedKeys: [GENUINE] }), true, []);
    });
  });

  test(`P5 [${s.name}] own trustedKeys stays authoritative under unrelated prototype pollution`, () => {
    withObjectPrototype({ trustedKeys: data([OTHER_ED25519]), allowUntrustedKey: data(true) }, () => {
      expectTrust("P5 own-correct", s.run({ now, trustedKeys: [GENUINE] }), true, []);
      expectTrust("P5 own-wrong", s.run({ now, trustedKeys: [OTHER_ED25519] }), false, ["key_untrusted"]);
    });
  });

  test(`P6a [${s.name}] throwing getters on a custom prototype are never invoked when not own`, () => {
    let invoked = 0;
    const proto = {};
    for (const key of ["trustedKeys", "allowUntrustedKey", "wholeOptionsInvalid"]) {
      Object.defineProperty(proto, key, { get() { invoked += 1; throw new Error(`prototype ${key} getter`); }, enumerable: true });
    }
    const opts = Object.assign(Object.create(proto), { now });
    expectTrust("P6a", s.run(opts), false, ["trust_config_missing"]);
    assert.equal(invoked, 0, "prototype getters must not be invoked");
  });

  test(`P6b [${s.name}] throwing Object.prototype getters are never invoked; own trustedKeys still evaluated`, () => {
    let invoked = 0;
    const throwing = (key: string): PropertyDescriptor => ({
      get() { invoked += 1; throw new Error(`Object.prototype ${key} getter`); },
      enumerable: false,
    });
    withObjectPrototype({ allowUntrustedKey: throwing("allowUntrustedKey"), wholeOptionsInvalid: throwing("wholeOptionsInvalid") }, () => {
      expectTrust("P6b", s.run({ now, trustedKeys: [GENUINE] }), true, []);
    });
    assert.equal(invoked, 0, "Object.prototype getters must not be invoked");
  });
}
