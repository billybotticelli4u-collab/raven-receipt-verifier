// detectReceiptNamespace tests. Detection is routing-only — the strict shape
// checks still run in the selected verifier — but the router must classify
// both real namespaces and refuse everything else.
import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { detectReceiptNamespace } from "../src/index.ts";

const readInput = (rel: string): unknown =>
  (JSON.parse(
    fs.readFileSync(fileURLToPath(new URL(rel, import.meta.url)), "utf8"),
  ) as { input: unknown }).input;

test("real vectors detect as their namespace", () => {
  assert.equal(
    detectReceiptNamespace(readInput("../fixtures/receipt-v1/valid-minimal.json")),
    "solana",
  );
  assert.equal(
    detectReceiptNamespace(readInput("../fixtures/receipt-evm-v1/valid-minimal-evm.json")),
    "evm",
  );
});

test("marker fields must appear together", () => {
  assert.equal(detectReceiptNamespace({ mintAddress: "m" }), null);
  assert.equal(detectReceiptNamespace({ slot: 1 }), null);
  assert.equal(detectReceiptNamespace({ tokenAddress: "0x0" }), null);
  assert.equal(detectReceiptNamespace({ blockNumber: 1 }), null);
  assert.equal(detectReceiptNamespace({ mintAddress: "m", slot: 1 }), "solana");
  assert.equal(detectReceiptNamespace({ tokenAddress: "0x0", blockNumber: 1 }), "evm");
});

test("non-object artifacts are refused", () => {
  assert.equal(detectReceiptNamespace(null), null);
  assert.equal(detectReceiptNamespace(undefined), null);
  assert.equal(detectReceiptNamespace("receipt"), null);
  assert.equal(detectReceiptNamespace(42), null);
  assert.equal(detectReceiptNamespace([{ mintAddress: "m", slot: 1 }]), null);
});
