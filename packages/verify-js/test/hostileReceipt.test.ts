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
  reasons: ["shape_not_an_object"],
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
  assert.deepEqual(r!.reasons, ["shape_not_an_object"]);
  assert.equal(r!.rulesVersion, null);
  assert.equal(r!.rulesStatus, "malformed");
  assert.deepEqual(r!.rulesReasons, ["malformed_rules_version"]);
  assert.ok(!("keyTrusted" in r!), "no trust option supplied => keyTrusted absent");
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
    r = verifyReceiptV1(revokedProxy(), { now: T0, trustedKeys: ["some-key"] });
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
  assert.deepEqual(r!.reasons, ["shape_not_an_object"]);
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

// Containment must not change the outcome for ordinary non-object inputs.
for (const [label, input] of [
  ["null", null],
  ["undefined", undefined],
  ["string", "not-a-receipt"],
  ["number", 42],
  ["boolean", true],
  ["array", [{ chain: "solana" }]],
] as Array<[string, unknown]>) {
  test(`non-object receipt (${label}) keeps its existing malformed outcome`, () => {
    const r = verifyReceiptV1(input, { now: T0 });
    assert.equal(r.valid, false);
    assert.equal(r.stale, false);
    assert.deepEqual(r.reasons, ["shape_not_an_object"]);
    assert.equal(r.rulesVersion, null);
    assert.equal(r.rulesStatus, "malformed");
    assert.deepEqual(r.rulesReasons, ["malformed_rules_version"]);
    assert.ok(!("keyTrusted" in r));
  });
}

test("a shape-invalid object keeps its field-level shape reasons", () => {
  const r = verifyReceiptV1({ chain: "solana" }, { now: T0 });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.length > 1, JSON.stringify(r.reasons));
  assert.ok(r.reasons.every((x) => x.startsWith("shape_missing_field:")), JSON.stringify(r.reasons));
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
  assert.deepEqual(result.reasons, []);
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
  assert.deepEqual(result.reasons, ["canonicalization_failed"]);
});

test("successfully read malformed or cryptographically wrong signature bytes stay signature_invalid", () => {
  for (const signature of ["!!!not-base64!!!", Buffer.alloc(64).toString("base64")]) {
    const result = contained({ ...validInput(), signature }, { now: validFixture.now });
    assert.equal(result.valid, false);
    assert.deepEqual(result.reasons, ["signature_invalid"]);
  }
});
