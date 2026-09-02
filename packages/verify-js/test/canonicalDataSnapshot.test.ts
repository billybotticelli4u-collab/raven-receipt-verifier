// canonicalDataSnapshot — the one stable capture behind
// verifyReceiptV1ForSubject. These tests pin the ported ACP admission
// semantics (#94): every declared field is read exactly once through its
// descriptor, hidden graph channels are rejected, and the result is a
// detached, deeply frozen JSON-data graph.

import assert from "node:assert/strict";
import test from "node:test";

import {
  CanonicalDataSnapshotError,
  canonicalDataSnapshot,
} from "../src/canonicalDataSnapshot.ts";

const OPTS = { maxNodes: 64, label: "test graph" } as const;

test("snapshot detaches nested data and expands shared aliases per occurrence", () => {
  const sharedChecks = ["largest_accounts", "token_supply"];
  const source = {
    coverageGaps: ["top_holders", "holder_venue_adjustment"],
    observation: { slot: 432_100_001, nested: { flag: true } },
    first: sharedChecks,
    second: sharedChecks,
  };

  const snapshot = canonicalDataSnapshot(source, OPTS);
  assert.notEqual(snapshot.coverageGaps, source.coverageGaps);
  assert.notEqual(snapshot.observation, source.observation);
  assert.notEqual(snapshot.first, snapshot.second);

  source.coverageGaps.length = 0;
  source.observation.nested.flag = false;
  sharedChecks.push("forged_after_capture");
  assert.deepEqual(snapshot.coverageGaps, ["top_holders", "holder_venue_adjustment"]);
  assert.equal(snapshot.observation.nested.flag, true);
  assert.deepEqual(snapshot.first, ["largest_accounts", "token_supply"]);
  assert.equal(Object.isFrozen(snapshot), true);
  assert.equal(Object.isFrozen(snapshot.observation.nested), true);
  assert.equal(Object.isFrozen(snapshot.first), true);
});

test("root primitives pass through; unsupported primitives are rejected", () => {
  assert.equal(canonicalDataSnapshot("solana-mainnet", OPTS), "solana-mainnet");
  assert.equal(canonicalDataSnapshot(true, OPTS), true);
  assert.equal(canonicalDataSnapshot(42, OPTS), 42);
  assert.equal(canonicalDataSnapshot(null, OPTS), null);
  for (const bad of [undefined, Number.NaN, Number.POSITIVE_INFINITY, () => 1, 10n]) {
    assert.throws(() => canonicalDataSnapshot(bad, OPTS), CanonicalDataSnapshotError);
  }
});

test("hidden graph channels are rejected without invoking accessors", () => {
  let getterCalls = 0;
  const getter = {};
  Object.defineProperty(getter, "mintAddress", {
    enumerable: true,
    get() {
      getterCalls += 1;
      return "forged";
    },
  });
  const nonEnumerable = {};
  Object.defineProperty(nonEnumerable, "mintAddress", {
    value: "forged",
    enumerable: false,
  });
  const symbol = { [Symbol("mintAddress")]: "forged" };
  const customPrototype = Object.create({ mintAddress: "forged" });
  const classInstance = new (class { mintAddress = "forged"; })();
  const cyclic: { self?: unknown } = {};
  cyclic.self = cyclic;

  for (const value of [getter, nonEnumerable, symbol, customPrototype, classInstance, cyclic]) {
    assert.throws(() => canonicalDataSnapshot(value, OPTS), CanonicalDataSnapshotError);
  }
  assert.equal(getterCalls, 0);
});

test("arrays must be dense plain data arrays", () => {
  const snapshot = canonicalDataSnapshot({ list: [1, "two", null] }, OPTS);
  assert.deepEqual(snapshot.list, [1, "two", null]);
  assert.deepEqual(Object.keys(snapshot), ["list"]);

  class ArraySubclass extends Array {}
  const subclassed = new ArraySubclass(1, 2);
  const sparse = [1, , 3]; // eslint-disable-line no-sparse-arrays
  const extended: unknown[] & { extra?: number } = [1, 2];
  extended.extra = 3;
  const accessorElement: unknown[] = [1, 2];
  Object.defineProperty(accessorElement, "0", {
    enumerable: true,
    get() {
      return 1;
    },
  });
  const nonEnumerableElement: unknown[] = [1, 2];
  Object.defineProperty(nonEnumerableElement, "0", {
    value: 1,
    enumerable: false,
  });

  for (const value of [subclassed, sparse, extended, accessorElement, nonEnumerableElement]) {
    assert.throws(() => canonicalDataSnapshot({ list: value }, OPTS), CanonicalDataSnapshotError);
  }
});

test("an array whose length descriptor is not a safe non-negative integer is rejected", () => {
  const lying = new Proxy([1, 2, 3], {
    getOwnPropertyDescriptor(target, prop) {
      if (prop === "length") {
        return { value: 1.5, enumerable: false, writable: true, configurable: false };
      }
      return Reflect.getOwnPropertyDescriptor(target, prop);
    },
  });
  assert.throws(() => canonicalDataSnapshot(lying, OPTS), CanonicalDataSnapshotError);
});

test("non-JSON values nested in the graph are rejected", () => {
  assert.throws(() => canonicalDataSnapshot({ a: undefined }, OPTS), CanonicalDataSnapshotError);
  assert.throws(() => canonicalDataSnapshot({ a: { b: Number.NaN } }, OPTS), CanonicalDataSnapshotError);
  assert.throws(() => canonicalDataSnapshot([() => 1], OPTS), CanonicalDataSnapshotError);
});

test("the copy budget is enforced", () => {
  const wide = { a: 1, b: 2, c: 3 };
  assert.throws(
    () => canonicalDataSnapshot(wide, { maxNodes: 2, label: "test graph" }),
    CanonicalDataSnapshotError,
  );
  // Budget exhaustion mid-array takes the same bounded path.
  assert.throws(
    () => canonicalDataSnapshot({ list: [1, 2, 3, 4, 5] }, { maxNodes: 3, label: "test graph" }),
    CanonicalDataSnapshotError,
  );
});

test("a revoked Proxy cannot be detached and never escapes a foreign TypeError", () => {
  const { proxy, revoke } = Proxy.revocable({ mintAddress: "forged" }, {});
  revoke();
  assert.throws(
    () => canonicalDataSnapshot(proxy, OPTS),
    (error: unknown) =>
      error instanceof CanonicalDataSnapshotError &&
      /cannot be safely detached/.test(error.message),
  );
});

test("null-prototype data objects are accepted", () => {
  const plain: Record<string, unknown> = Object.create(null);
  plain.chain = "solana-mainnet";
  const snapshot = canonicalDataSnapshot(plain, OPTS);
  assert.equal(snapshot.chain, "solana-mainnet");
  assert.equal(Object.getPrototypeOf(snapshot), null);
  assert.equal(Object.isFrozen(snapshot), true);
});
