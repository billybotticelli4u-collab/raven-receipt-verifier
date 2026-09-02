// D3 regression: receipt-v1 signatures are Ed25519-only (SPEC §3).
//
// At 1b093a91 the verifier built a public key from whatever SPKI the receipt
// carried and called cryptoVerify(null, …), so the attacker's key chose the
// algorithm: a receipt self-signed with an RSA-2048 or EC P-256 key verified
// valid:true while the Python reference verifier returned signature_invalid.
// These tests pin the corrected behavior: non-Ed25519 signer keys are
// rejected with signature_invalid, and a genuine Ed25519 self-signed receipt
// (attacker key, but correct algorithm) still passes the signature axis —
// key trust remains a separate, non-fatal axis.
//
// Vectors are constructed by tampering a shipped fixture and re-signing with
// a fresh attacker key, the same construction as the permanent conformance
// vectors in conformance/inputs/d3-{rsa,ec}.json (PR: §6 ledger).

import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  verifyReceiptV1,
  canonicalJson,
  RECEIPT_BODY_FIELDS,
} from "../src/index.ts";

const FIXTURE = fileURLToPath(new URL("../fixtures/receipt-v1/valid-minimal.json", import.meta.url));
const VECTOR = JSON.parse(fs.readFileSync(FIXTURE, "utf8")) as {
  input: Record<string, unknown>;
  now: string;
};

// Tamper the fixture, repair payloadHash/receiptId so every check except the
// signature axis passes, then self-sign with a fresh key of the given kind.
const resignAsAttacker = (kind: "ed25519" | "rsa" | "ec"): Record<string, unknown> => {
  const r: Record<string, unknown> = JSON.parse(JSON.stringify(VECTOR.input));
  r.mintAddress = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263"; // tamper
  const body = Object.fromEntries(RECEIPT_BODY_FIELDS.map((f) => [f, r[f]]));
  r.payloadHash = "sha256:" + createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
  r.receiptId = "raven-receipt-v1:" + (r.payloadHash as string);
  const envelope = Buffer.from(
    canonicalJson({ domain: "raven-receipt", version: "v1", payloadHash: r.payloadHash }),
    "utf8",
  );
  const { publicKey, privateKey } =
    kind === "ed25519"
      ? generateKeyPairSync("ed25519")
      : kind === "rsa"
        ? generateKeyPairSync("rsa", { modulusLength: 2048 })
        : generateKeyPairSync("ec", { namedCurve: "P-256" });
  r.signerPublicKey = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const sig = kind === "ed25519" ? cryptoSign(null, envelope, privateKey) : cryptoSign("sha256", envelope, privateKey);
  r.signature = sig.toString("base64");
  return r;
};

test("control: Ed25519 self-signed tampered receipt passes the signature axis", () => {
  const r = verifyReceiptV1(resignAsAttacker("ed25519"), { now: VECTOR.now });
  assert.equal(r.valid, true, JSON.stringify(r.reasons));
  assert.deepEqual(r.reasons, []);
});

test("CR-1: Ed25519 SPKI with trailing DER bytes is rejected", () => {
  const receipt = resignAsAttacker("ed25519");
  const canonical = Buffer.from(receipt.signerPublicKey as string, "base64");
  receipt.signerPublicKey = Buffer.concat([canonical, Buffer.of(0)]).toString("base64");
  const r = verifyReceiptV1(receipt, { now: VECTOR.now });
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["signature_invalid"]);
});

test("D3: RSA-2048 self-signed receipt is rejected (signature_invalid)", () => {
  const r = verifyReceiptV1(resignAsAttacker("rsa"), { now: VECTOR.now });
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["signature_invalid"]);
});

test("D3: EC P-256 self-signed receipt is rejected (signature_invalid)", () => {
  const r = verifyReceiptV1(resignAsAttacker("ec"), { now: VECTOR.now });
  assert.equal(r.valid, false);
  assert.deepEqual(r.reasons, ["signature_invalid"]);
});
