// Hostile-receipt containment — a receipt that cannot even be type-inspected
// must still produce an outcome, never an exception.
//
// A revoked Proxy makes `Array.isArray` itself raise a TypeError, so the entry
// guard `receipt === null || typeof receipt !== "object" || Array.isArray(...)`
// throws straight out of the verifier. The rules evaluator's `isObject` helper
// carries the identical hazard and is reached with the raw receipt on the
// non-object branch, so containing only the entry guard leaves the escape live
// one line later.
//
// Ported from the ACP surface (#93). This is RECEIPT containment: it is
// reachable with no trust options supplied, so it is independent of the
// trust-input contract in trustConfig.test.ts.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { verifyReceiptV1, evaluateReceiptRules } from "../src/index.ts";
import { verifyReceiptEvmV1 } from "../src/proposed.ts";

const revokedProxy = (): Record<string, unknown> => {
  const { proxy, revoke } = Proxy.revocable<Record<string, unknown>>({ chain: "solana" }, {});
  revoke();
  return proxy;
};

const T0 = "2026-06-19T12:00:00.000Z";

const validFixture = JSON.parse(
  readFileSync(
    new URL("../fixtures/receipt-v1/rules-1.1.4-state-a-valid.json", import.meta.url),
    "utf8",
  ),
) as {
  input: Record<string, unknown>;
  now: string;
};

const findingsFixture = JSON.parse(
  readFileSync(
    new URL("../fixtures/receipt-v1/rules-1.1.4-state-b-valid.json", import.meta.url),
    "utf8",
  ),
) as {
  input: Record<string, unknown>;
  now: string;
};

const validInput = (): Record<string, unknown> => structuredClone(validFixture.input);

const HOSTILE_RESULT = {
  valid: false,
  stale: false,
  reasons: ["shape_not_an_object", "trust_config_missing"],
  keyTrusted: false,
  rulesVersion: null,
  rulesStatus: "malformed",
  rulesReasons: ["malformed_rules_version"],
};

const ownKeysTrap = (target: Record<string, unknown>): Record<string, unknown> =>
  new Proxy(target, {
    ownKeys() {
      throw new TypeError("hostile ownKeys");
    },
  });

const descriptorTrap = (target: Record<string, unknown>): Record<string, unknown> =>
  new Proxy(target, {
    getOwnPropertyDescriptor() {
      throw new TypeError("hostile getOwnPropertyDescriptor");
    },
  });

const hasTrap = (target: Record<string, unknown>): Record<string, unknown> =>
  new Proxy(target, {
    has() {
      throw new TypeError("hostile has");
    },
  });

const requiredGetterTrap = (target: Record<string, unknown>): Record<string, unknown> => {
  Object.defineProperty(target, "chain", {
    enumerable: true,
    configurable: true,
    get() {
      throw new TypeError("hostile chain getter");
    },
  });
  return target;
};

const nestedShapeGetterTrap = (target: Record<string, unknown>): Record<string, unknown> => {
  const gaps = [...(target.coverageGaps as string[])];
  Object.defineProperty(gaps, "0", {
    enumerable: true,
    configurable: true,
    get() {
      throw new TypeError("hostile coverageGaps getter");
    },
  });
  target.coverageGaps = gaps;
  return target;
};

const postShapeTrap = (
  target: Record<string, unknown>,
  field: string,
): Record<string, unknown> => {
  let shapeComplete = false;
  return new Proxy(target, {
    get(object, property, receiver) {
      if (shapeComplete && property === field) {
        throw new TypeError(`hostile post-shape ${field}`);
      }
      const value = Reflect.get(object, property, receiver);
      if (property === "signerPublicKey") shapeComplete = true;
      return value;
    },
  });
};

const oneShotTrap = (
  target: Record<string, unknown>,
  field: string,
  throwOnRead: number,
): { receipt: Record<string, unknown>; fired: () => boolean } => {
  let reads = 0;
  let fired = false;
  const receipt = new Proxy(target, {
    get(object, property, receiver) {
      if (property === field && ++reads === throwOnRead) {
        fired = true;
        throw new TypeError(`one-shot ${field} #${throwOnRead}`);
      }
      return Reflect.get(object, property, receiver);
    },
  });
  return { receipt, fired: () => fired };
};

const contained = (input: unknown, opts: Parameters<typeof verifyReceiptV1>[1] = {}) => {
  let result: ReturnType<typeof verifyReceiptV1> | undefined;
  let sentinel = false;
  assert.doesNotThrow(() => {
    result = verifyReceiptV1(input, opts);
    sentinel = true;
  });
  assert.equal(sentinel, true, "caller execution must continue after verification");
  return result!;
};

test("a revoked-Proxy receipt is contained: an outcome, never an exception", () => {
  let r: ReturnType<typeof verifyReceiptV1> | undefined;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1(revokedProxy(), { now: T0 });
  });
  assert.equal(r!.valid, false);
  assert.equal(r!.stale, false);
  assert.deepEqual(r!.reasons, ["shape_not_an_object", "trust_config_missing"]);
  assert.equal(r!.rulesVersion, null);
  assert.equal(r!.rulesStatus, "malformed");
  assert.deepEqual(r!.rulesReasons, ["malformed_rules_version"]);
  assert.equal(r!.keyTrusted, false, "omitted trust config must fail closed");
});

test("a revoked-Proxy receipt is contained with trust options supplied too", () => {
  // Containment is this test's property and is unchanged: no exception escapes,
  // `valid` is false, and the shape reason is still reported first.
  //
  // The trust axis is now ALSO resolved on this path (see
  // trustConfigShapeFailure.test.ts). A revoked Proxy has no readable
  // `signerPublicKey`, so trust resolves CLOSED — `keyTrusted: false` with
  // `key_untrusted` appended after the shape reason. That is the settled
  // cross-surface contract: the ACP verifier asserts exactly this for a
  // hostile-signer receipt in receipt-v1-trust-config.test.ts (#90).
  //
  // The assertion is strengthened rather than relaxed — `keyTrusted` is now
  // pinned explicitly, where before it was only implied by its absence.
  let r: ReturnType<typeof verifyReceiptV1> | undefined;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1(revokedProxy(), {
      now: T0,
      trustedKeys: [validFixture.input.signerPublicKey as string],
    });
  });
  assert.equal(r!.valid, false);
  assert.equal(r!.keyTrusted, false, "a receipt with no readable signer is never trusted");
  assert.deepEqual(r!.reasons, ["shape_not_an_object", "key_untrusted"]);
});

test("the EVM verifier contains a revoked-Proxy receipt as well", () => {
  let r: ReturnType<typeof verifyReceiptEvmV1> | undefined;
  assert.doesNotThrow(() => {
    r = verifyReceiptEvmV1(revokedProxy(), { now: T0 });
  });
  assert.equal(r!.valid, false);
  assert.equal(r!.keyTrusted, false);
  assert.deepEqual(r!.reasons, ["shape_not_an_object", "trust_config_missing"]);
});

test("the rules evaluator alone contains a revoked Proxy", () => {
  let out: ReturnType<typeof evaluateReceiptRules> | undefined;
  assert.doesNotThrow(() => {
    out = evaluateReceiptRules(revokedProxy(), false);
  });
  assert.equal(out!.rulesVersion, null);
  assert.equal(out!.rulesStatus, "malformed");
  assert.deepEqual(out!.rulesReasons, ["malformed_rules_version"]);
});

// Containment must not drop the trust axis for ordinary non-object inputs.
for (const [label, input] of [
  ["null", null],
  ["undefined", undefined],
  ["string", "not-a-receipt"],
  ["number", 42],
  ["boolean", true],
  ["array", [{ chain: "solana" }]],
] as Array<[string, unknown]>) {
  test(`non-object receipt (${label}) reports malformed shape and missing trust config`, () => {
    const r = verifyReceiptV1(input, { now: T0 });
    assert.equal(r.valid, false);
    assert.equal(r.stale, false);
    assert.deepEqual(r.reasons, ["shape_not_an_object", "trust_config_missing"]);
    assert.equal(r.rulesVersion, null);
    assert.equal(r.rulesStatus, "malformed");
    assert.deepEqual(r.rulesReasons, ["malformed_rules_version"]);
    assert.equal(r.keyTrusted, false);
  });
}

test("a shape-invalid object keeps its field-level shape reasons", () => {
  const r = verifyReceiptV1({ chain: "solana" }, { now: T0 });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.length > 1, JSON.stringify(r.reasons));
  assert.ok(
    r.reasons.slice(0, -1).every((x) => x.startsWith("shape_missing_field:")),
    JSON.stringify(r.reasons),
  );
  assert.equal(r.reasons.at(-1), "trust_config_missing");
  assert.equal(r.keyTrusted, false);
  assert.equal(r.reasons.includes("shape_not_an_object"), false);
});

// The containment must not blanket-null the rules input: a shape-invalid object
// carrying a rulesVersion must still reach the rules evaluator normally.
test("a shape-invalid object with a rulesVersion still reaches the rules evaluator", () => {
  const r = verifyReceiptV1({ chain: "solana", rulesVersion: "1.1.4" }, { now: T0 });
  assert.equal(r.valid, false);
  assert.equal(r.rulesVersion, "1.1.4");
  assert.notEqual(r.rulesStatus, "malformed");
});

// Customer-path hostile live-object matrix. These are all property-access
// failures, not malformed bytes: the closed taxonomy is shape_not_an_object.
const hostileCases: ReadonlyArray<readonly [string, (r: Record<string, unknown>) => unknown]> = [
  ["ownKeys trap", ownKeysTrap],
  ["getOwnPropertyDescriptor trap", descriptorTrap],
  ["has trap", hasTrap],
  ["throwing required-field getter", requiredGetterTrap],
  ["nested shape-inspected getter", nestedShapeGetterTrap],
  ["post-shape chain getter", (r) => postShapeTrap(r, "chain")],
  ["post-shape signature accessor", (r) => postShapeTrap(r, "signature")],
  ["post-shape signer accessor", (r) => postShapeTrap(r, "signerPublicKey")],
];

for (const [label, makeHostile] of hostileCases) {
  test(`${label} is contained with the exact bounded result`, () => {
    assert.deepEqual(
      contained(makeHostile(validInput()), { now: validFixture.now }),
      HOSTILE_RESULT,
    );
  });
}

test("the valid signed receipt remains valid through the same exported path", () => {
  const result = contained(validInput(), { now: validFixture.now });
  assert.equal(result.valid, true);
  assert.equal(result.keyTrusted, false);
  assert.deepEqual(result.reasons, ["trust_config_missing"]);
});

test("the hostile-result assertion is non-vacuous", () => {
  const result = contained(ownKeysTrap(validInput()), { now: validFixture.now });
  assert.throws(
    () => assert.deepEqual(result.reasons, ["signature_invalid"]),
    /signature_invalid/,
  );
});

for (const field of ["signature", "signerPublicKey"]) {
  test(`one-shot ${field} accessor on the crypto read reaches the boundary`, () => {
    const trap = oneShotTrap(validInput(), field, 2);
    const result = contained(trap.receipt, { now: validFixture.now });
    assert.equal(trap.fired(), true, "the one-shot trap must fire or the probe proves nothing");
    assert.deepEqual(result, HOSTILE_RESULT);
  });
}

test("the boundary remains total with both a hostile signer and hostile trustedKeys", () => {
  const hostileKeys = new Proxy([] as string[], {
    get(target, property, receiver) {
      if (property === Symbol.iterator || property === "length") {
        throw new TypeError("hostile trustedKeys");
      }
      return Reflect.get(target, property, receiver);
    },
  });
  const result = contained(postShapeTrap(validInput(), "signerPublicKey"), {
    now: validFixture.now,
    trustedKeys: hostileKeys,
  });
  assert.equal(result.valid, false);
  assert.deepEqual(result.reasons.slice(0, 1), ["shape_not_an_object"]);
  assert.equal(result.keyTrusted, false);
  assert.equal(result.rulesVersion, null);
  assert.equal(result.rulesStatus, "malformed");
});

test("a deep getter reached only during canonicalization stays canonicalization_failed", () => {
  const input = structuredClone(findingsFixture.input);
  const findings = input.findings as Array<Record<string, unknown>>;
  const evidence = findings[0]!.evidence as Record<string, unknown>;
  Object.defineProperty(evidence, "hostileNestedGetter", {
    enumerable: true,
    configurable: true,
    get() {
      throw new TypeError("hostile nested evidence getter");
    },
  });
  const result = contained(input, { now: findingsFixture.now });
  assert.equal(result.valid, false);
  assert.equal(result.keyTrusted, false);
  assert.deepEqual(result.reasons, ["canonicalization_failed", "trust_config_missing"]);
});

test("successfully read malformed or cryptographically wrong signature bytes stay signature_invalid", () => {
  for (const signature of ["!!!not-base64!!!", Buffer.alloc(64).toString("base64")]) {
    const result = contained({ ...validInput(), signature }, { now: validFixture.now });
    assert.equal(result.valid, false);
    assert.equal(result.keyTrusted, false);
    assert.deepEqual(result.reasons, ["signature_invalid", "trust_config_missing"]);
  }
});

// --- A caller's Date option is not a receipt read ---------------------------
//
// The containment above is for RECEIPT values: a receipt that cannot be read
// must still produce an outcome. Converting the caller's own `now` option is
// not a receipt read. When that conversion fails the caller made the mistake,
// so the caller keeps the exception they would have seen before containment
// existed. Reporting `shape_not_an_object` plus `malformed_rules_version` would
// blame the receipt for the caller's option and make diagnostics untrustworthy.
// No new reason or status is introduced by these cases.
//
// The assertions are on OBJECT IDENTITY, not class and message: rethrowing a
// newly constructed error of the same class and message hands the caller a
// different value, and must fail here.

/** The exact object the subclass throws, created outside it so identity is testable. */
const nowFailure = new TypeError("hostile now");

class ThrowingDate extends Date {
  toISOString(): string {
    throw nowFailure;
  }
}

/** An invalid Date that records the engine's own RangeError, so its identity can be asserted. */
class CapturingInvalidDate extends Date {
  thrown: unknown = undefined;
  toISOString(): string {
    try {
      return super.toISOString();
    } catch (error) {
      this.thrown = error;
      throw error;
    }
  }
}

/** The value `run` threw, boxed so that a thrown `undefined` is distinguishable from no throw. */
const thrownBy = (run: () => unknown): { value: unknown } => {
  try {
    run();
  } catch (error) {
    return { value: error };
  }
  assert.fail("the call was expected to throw");
};

/** A receipt whose `chain` read throws `value`, whatever `value` is. */
const receiptThrowing = (value: unknown): Record<string, unknown> =>
  new Proxy(validInput(), {
    get(target, property, receiver) {
      if (property === "chain") throw value;
      return Reflect.get(target, property, receiver);
    },
  });

test("an invalid Date `now` keeps its own RangeError instead of blaming the receipt", () => {
  assert.throws(
    () => verifyReceiptV1(validInput(), { now: new Date(NaN) }),
    RangeError,
    "a documented Date option failure must retain its pre-containment exception",
  );
});

test("the invalid-Date RangeError is the engine's own object, not a copy", () => {
  const now = new CapturingInvalidDate(NaN);
  const caught = thrownBy(() => verifyReceiptV1(validInput(), { now }));
  assert.ok(now.thrown instanceof RangeError, "control: the engine must have thrown a RangeError");
  assert.strictEqual(caught.value, now.thrown, "a reconstructed RangeError is not the original");
});

test("a throwing Date subclass preserves the exact object it threw", () => {
  const caught = thrownBy(() => verifyReceiptV1(validInput(), { now: new ThrowingDate(T0) }));
  assert.strictEqual(
    caught.value,
    nowFailure,
    "a reconstructed error of the same class and message is not the original",
  );
});

// Whatever the caller's `toISOString` throws comes back unchanged, so the
// contract cannot be met by matching error classes.
const arbitraryOptionThrows: [string, unknown][] = [
  ["a frozen plain object", Object.freeze({ raven: "not an error" })],
  ["a string", "plain string failure"],
  ["undefined", undefined],
  ["null", null],
  ["false", false],
  ["zero", 0],
  ["a symbol", Symbol("date option failure")],
  ["a function", function hostileNow() {}],
  ["a revoked Proxy", revokedProxy()],
];

for (const [label, value] of arbitraryOptionThrows) {
  test(`a Date option that throws ${label} gets that exact value back`, () => {
    class Thrower extends Date {
      toISOString(): string {
        throw value;
      }
    }
    const caught = thrownBy(() => verifyReceiptV1(validInput(), { now: new Thrower(T0) }));
    assert.strictEqual(caught.value, value);
  });
}

test("an ordinary Date `now` still verifies the valid receipt", () => {
  const result = contained(validInput(), { now: new Date(validFixture.now) });
  assert.equal(result.valid, true);
  assert.deepEqual(result.reasons, ["trust_config_missing"]);
});

test("a hostile receipt stays contained even when the Date option is also invalid", () => {
  // Receipt containment still wins: the receipt fails long before freshness.
  assert.deepEqual(contained(revokedProxy(), { now: new Date(NaN) }), HOSTILE_RESULT);
});

// Whatever a RECEIPT throws stays contained. Non-objects take the boundary's
// early return; objects are looked up by private identity and never matched by
// shape, message or prototype.
const receiptThrows: [string, unknown][] = [
  ["null", null],
  ["undefined", undefined],
  ["a string", "not an object"],
  ["a number", 42],
  ["a symbol", Symbol("receipt failure")],
  ["a function", function hostileReceipt() {}],
  ["a Date-option lookalike RangeError", new RangeError("Invalid time value")],
  ["the very object a Date option once threw", nowFailure],
  ["a revoked Proxy", revokedProxy()],
];

for (const [label, value] of receiptThrows) {
  test(`a receipt that throws ${label} stays contained`, () => {
    assert.deepEqual(contained(receiptThrowing(value), { now: T0 }), HOSTILE_RESULT);
  });
}

test("a receipt that throws a value with a hostile getPrototypeOf stays contained, trap untouched", () => {
  // `instanceof` on the thrown value would run this trap and escape the
  // boundary; a closure-private identity lookup never consults it.
  let consulted = false;
  const hostilePrototype = new Proxy(
    {},
    {
      getPrototypeOf() {
        consulted = true;
        throw new TypeError("hostile getPrototypeOf");
      },
    },
  );
  assert.deepEqual(contained(receiptThrowing(hostilePrototype), { now: T0 }), HOSTILE_RESULT);
  assert.equal(consulted, false, "the boundary must not consult the thrown value's prototype");
});
