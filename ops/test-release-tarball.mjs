import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";

import { measureReleaseArtifact, npmCommand, parseArgs, run } from "./release-artifact-utils.mjs";

const args = parseArgs(process.argv);
const packageDir = path.resolve(args["package-dir"] ?? "packages/verify-js");
const measured = measureReleaseArtifact({
  packJsonPath: path.resolve(args["pack-json"]),
  tarballDir: path.resolve(args["tarball-dir"]),
});
const scratch = mkdtempSync(path.join(tmpdir(), "raven-customer-blackbox-"));
const consumer = path.join(scratch, "consumer");
const tsc = path.join(packageDir, "node_modules", "typescript", "bin", "tsc");

try {
  run(npmCommand(), ["init", "--yes"], { cwd: scratch });
  run(npmCommand(), ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--offline", measured.tarball], { cwd: scratch });
  mkdirSync(consumer);
  for (const fixture of ["valid-minimal.json", "production-receipt-v1-bonk-verified.json", "rules-future-unsupported.json"]) {
    copyFileSync(path.join(packageDir, "fixtures/receipt-v1", fixture), path.join(consumer, fixture));
  }
  writeFileSync(path.join(consumer, "verify.mjs"), `
import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import { readFileSync } from "node:fs";
import * as pkg from "raven-receipt-verifier";

const vector = JSON.parse(readFileSync(new URL("./valid-minimal.json", import.meta.url), "utf8"));
const production = JSON.parse(readFileSync(new URL("./production-receipt-v1-bonk-verified.json", import.meta.url), "utf8"));
const future = JSON.parse(readFileSync(new URL("./rules-future-unsupported.json", import.meta.url), "utf8"));
const { canonicalJson, RECEIPT_BODY_FIELDS, verifyReceiptV1, verifyReceiptV1ForSubject, ravenProductionTrustedKeys } = pkg;

const resign = (kind) => {
  const receipt = structuredClone(vector.input);
  receipt.mintAddress = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
  const body = Object.fromEntries(RECEIPT_BODY_FIELDS.map((field) => [field, receipt[field]]));
  receipt.payloadHash = "sha256:" + createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
  receipt.receiptId = "raven-receipt-v1:" + receipt.payloadHash;
  const envelope = Buffer.from(canonicalJson({ domain: "raven-receipt", version: "v1", payloadHash: receipt.payloadHash }));
  const pair = kind === "ed25519"
    ? generateKeyPairSync("ed25519")
    : kind === "rsa"
      ? generateKeyPairSync("rsa", { modulusLength: 2048 })
      : generateKeyPairSync("ec", { namedCurve: "P-256" });
  receipt.signerPublicKey = pair.publicKey.export({ type: "spki", format: "der" }).toString("base64");
  receipt.signature = cryptoSign(kind === "ed25519" ? null : "sha256", envelope, pair.privateKey).toString("base64");
  return receipt;
};

const productionOptions = { now: production.now, trustedKeys: ravenProductionTrustedKeys() };
const good = verifyReceiptV1(production.input, productionOptions);
assert.equal(good.valid, true);
assert.equal(good.keyTrusted, true);
assert.equal(good.stale, false);

const wrongPin = verifyReceiptV1(production.input, { now: production.now, trustedKeys: [] });
assert.equal(wrongPin.valid, true);
assert.equal(wrongPin.keyTrusted, false);
assert.ok(wrongPin.reasons.includes("key_untrusted"));

for (const kind of ["ec", "rsa"]) {
  const receipt = resign(kind);
  const result = verifyReceiptV1(receipt, { now: vector.now, trustedKeys: [receipt.signerPublicKey] });
  assert.equal(result.valid, false, kind);
  assert.equal(result.keyTrusted, false, kind);
  assert.deepEqual(result.reasons, ["signature_invalid", "trust_key_type_unsupported"], kind);
}

const omitted = verifyReceiptV1(production.input, { now: production.now });
assert.equal(omitted.keyTrusted, false);
assert.ok(omitted.reasons.includes("trust_config_invalid"));
const optedOut = verifyReceiptV1(production.input, { now: production.now, allowUntrustedKey: true });
assert.equal(optedOut.valid, true);
assert.equal(optedOut.keyTrusted, false);
assert.ok(optedOut.reasons.includes("key_trust_not_evaluated"));

const subject = { chain: production.input.chain, mintAddress: production.input.mintAddress, tokenProgramAddress: production.input.tokenProgramAddress };
assert.equal(verifyReceiptV1ForSubject(production.input, subject, productionOptions).subjectMatches, true);
assert.equal(verifyReceiptV1ForSubject(production.input, { ...subject, mintAddress: "So11111111111111111111111111111111111111112" }, productionOptions).subjectMatches, false);

assert.equal(verifyReceiptV1(production.input, { ...productionOptions, now: "2030-01-01T00:00:00.000Z" }).stale, true);
assert.equal(verifyReceiptV1(null, { trustedKeys: [] }).valid, false);
const proxy = Proxy.revocable({}, {}); proxy.revoke();
assert.doesNotThrow(() => verifyReceiptV1(proxy.proxy, { trustedKeys: [] }));
const futureResult = verifyReceiptV1(future.input, { now: future.now, allowUntrustedKey: true });
assert.equal(futureResult.rulesStatus, "unsupported");

for (const withheld of ["verifyReceiptEvmV1", "verifyManifestChain", "receiptEvmV1"]) assert.equal(withheld in pkg, false);
await assert.rejects(import("raven-receipt-verifier/dist/verifyReceiptEvmV1.js"));
console.log(JSON.stringify({ node: process.version, valid: good.valid, keyTrusted: good.keyTrusted, p256: "rejected", rsa: "rejected", rules: futureResult.rulesStatus }));
`, "utf8");

  writeFileSync(path.join(consumer, "verify.cjs"), `
const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { ravenProductionTrustedKeys, verifyReceiptV1 } = require("raven-receipt-verifier");
const production = JSON.parse(readFileSync(__dirname + "/production-receipt-v1-bonk-verified.json", "utf8"));
const result = verifyReceiptV1(production.input, { now: production.now, trustedKeys: ravenProductionTrustedKeys() });
assert.equal(result.valid, true); assert.equal(result.keyTrusted, true);
console.log(JSON.stringify({ node: process.version, cjs: true, valid: result.valid }));
`, "utf8");

  writeFileSync(path.join(scratch, "consumer.ts"), `
import { verifyReceiptV1, verifyReceiptV1ForSubject, type VerifyReceiptResult } from "raven-receipt-verifier";
const result: VerifyReceiptResult = verifyReceiptV1({}, { allowUntrustedKey: true });
const trusted: boolean = result.keyTrusted;
const subject = verifyReceiptV1ForSubject({}, { chain: "solana-mainnet", mintAddress: "So11111111111111111111111111111111111111112", tokenProgramAddress: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA" }, { allowUntrustedKey: true });
const match: boolean | null = subject.subjectMatches;
void trusted; void match;
`, "utf8");
  writeFileSync(path.join(scratch, "tsconfig.json"), `${JSON.stringify({ compilerOptions: { target: "ES2022", module: "NodeNext", moduleResolution: "NodeNext", strict: true, noEmit: true, skipLibCheck: true, types: [] }, include: ["consumer.ts"] }, null, 2)}\n`);

  const noStrip = process.allowedNodeEnvironmentFlags.has("--no-experimental-strip-types") ? ["--no-experimental-strip-types"] : [];
  const esm = run(process.execPath, [...noStrip, "verify.mjs"], { cwd: consumer });
  const cjs = run(process.execPath, ["verify.cjs"], { cwd: consumer });
  run(process.execPath, [tsc, "-p", "tsconfig.json"], { cwd: scratch });
  const installed = JSON.parse(readFileSync(path.join(scratch, "node_modules/raven-receipt-verifier/package.json"), "utf8"));
  if (Object.keys(installed.dependencies ?? {}).length !== 0) throw new Error("installed package has runtime dependencies");
  console.log(`customer tarball verified: ${measured.tarball}`);
  console.log(`actual tgz SHA-512: ${measured.actual.sha512}`);
  console.log(esm);
  console.log(cjs);
  console.log("declaration consumer: PASS");
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
