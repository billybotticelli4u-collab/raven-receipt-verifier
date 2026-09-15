// Documentation guard (Phase-B blocker 2): the shipped READMEs must teach the
// trust-reason contract the verifier implements, proposition-bound, not merely
// mention the words somewhere.
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { contradictionsIn, missingRows, propositionsOf, codesOf } from "./helpers/readmeTrustContract.ts";

const read = (rel: string) => fs.readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8");
const VERIFY_JS_README = read("../README.md");
const PYTHON_README_REL = "../../../reference-verifiers/python/README.md";
const PYTHON_README_PATH = fileURLToPath(new URL(PYTHON_README_REL, import.meta.url));
const PYTHON_README = fs.existsSync(PYTHON_README_PATH) ? read(PYTHON_README_REL) : null;

test("checker self-test: it detects each forbidden teaching", () => {
  const forbidden = [
    "Omitting the trust policy returns `trust_config_invalid`.",
    "A malformed trust policy returns `trust_config_missing`.",
    "A non-Ed25519 SPKI supplied in `trustedKeys` fails with `trust_key_type_unsupported`.",
    "A non-Ed25519 receipt signer checked against an Ed25519 trust set reports `trust_config_invalid`.",
  ];
  for (const f of forbidden) assert.ok(contradictionsIn(f).length > 0, `must flag: ${f}`);
  const allowed = [
    "Omitting the trust policy returns `trust_config_missing`.",
    "A present but malformed trust policy returns `trust_config_invalid`.",
    "A non-Ed25519 key in `trustedKeys` is malformed trust configuration (`trust_config_invalid`); a non-Ed25519 receipt signer reports `trust_key_type_unsupported`.",
    "The CLI exits non-zero unless `keyTrusted` is true.",
  ];
  for (const a of allowed) assert.deepEqual(contradictionsIn(a), [], `must allow: ${a}`);
  assert.deepEqual(propositionsOf("Omitting both, or passing a malformed policy, returns `trust_config_missing`"), ["omission", "malformed"]);
  assert.deepEqual(codesOf("`trust_config_invalid` (malformed) or `trust_config_missing` (omission)"), ["trust_config_invalid", "trust_config_missing"]);
});

test("verify-js README never teaches missing→invalid, malformed→missing, or non-Ed25519 pin material→unsupported-signer", () => {
  assert.deepEqual(contradictionsIn(VERIFY_JS_README), []);
});

test("verify-js README carries the canonical trust-reason table", () => {
  assert.deepEqual(missingRows(VERIFY_JS_README), []);
});

test("python README never contradicts the trust-reason contract", (t) => {
  if (PYTHON_README === null) {
    t.skip("reference-verifiers/python README absent (standalone public checkout)");
    return;
  }
  assert.deepEqual(contradictionsIn(PYTHON_README), []);
});
