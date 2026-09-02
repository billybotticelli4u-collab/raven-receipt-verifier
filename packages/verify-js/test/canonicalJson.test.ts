// canonicalJson edge tests. Canonicalization bugs are signature bugs — every
// rejection rule in the SPEC's canonical-JSON section is pinned here so a
// refactor can't silently start accepting (or emitting) non-canonical bytes.
import assert from "node:assert/strict";
import test from "node:test";

import { CanonicalJsonError, canonicalJson, canonicalJsonStringify } from "../src/index.ts";

test("objects canonicalize with recursively sorted keys and no whitespace", () => {
  const canonical = canonicalJson({
    b: 2,
    a: { z: [3, 1], y: "text" },
  });

  assert.equal(canonical, '{"a":{"y":"text","z":[3,1]},"b":2}');
});

test("undefined properties are omitted; scalars and empty containers round-trip", () => {
  assert.equal(canonicalJson({ a: 1, gone: undefined }), '{"a":1}');
  assert.equal(canonicalJson(null), "null");
  assert.equal(canonicalJson(true), "true");
  assert.equal(canonicalJson(false), "false");
  assert.equal(canonicalJson("s"), '"s"');
  assert.equal(canonicalJson([]), "[]");
  assert.equal(canonicalJson({}), "{}");
});

test("arrays preserve order (only object keys sort)", () => {
  assert.equal(canonicalJson([3, 1, 2]), "[3,1,2]");
});

test("non-finite numbers and bigint are rejected, never coerced", () => {
  for (const bad of [NaN, Infinity, -Infinity]) {
    assert.throws(() => canonicalJson({ n: bad }), CanonicalJsonError);
  }
  assert.throws(() => canonicalJson({ n: 1n }), CanonicalJsonError);
});

test("bare undefined, functions, and symbols are rejected", () => {
  assert.throws(() => canonicalJson(undefined), CanonicalJsonError);
  assert.throws(() => canonicalJson({ f: [() => 1] }), CanonicalJsonError);
  assert.throws(() => canonicalJson([Symbol("s")]), CanonicalJsonError);
});

test("cycles are detected in objects and arrays; repeated references are fine", () => {
  const obj: Record<string, unknown> = {};
  obj.self = obj;
  assert.throws(() => canonicalJson(obj), /cycle detected/);

  const arr: unknown[] = [];
  arr.push(arr);
  assert.throws(() => canonicalJson(arr), /cycle detected/);

  // A DAG (same node referenced twice, no cycle) must canonicalize.
  const shared = { k: 1 };
  assert.equal(canonicalJson({ a: shared, b: shared }), '{"a":{"k":1},"b":{"k":1}}');
});

test("canonicalJsonStringify is the same function under the producer-app name", () => {
  assert.equal(canonicalJsonStringify, canonicalJson);
});
