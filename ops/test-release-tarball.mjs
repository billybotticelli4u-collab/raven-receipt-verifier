// Exercises the already-packed tarball from the artifact handoff. This script
// deliberately does not run `npm pack`; it proves the artifact uploaded by the
// pack job works for ESM, CJS, declarations, file inventory, zero dependencies,
// trust-anchor recognition, subject binding, and withheld-surface containment.
import assert from "node:assert/strict";
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import {
  assertCustomerPackage,
  npmCommand,
  parseArgs,
  readJson,
  resolveTarballPath,
  run,
} from "./release-artifact-utils.mjs";

const args = parseArgs(process.argv);
const packageDir = path.resolve(args["package-dir"] ?? "packages/verify-js");
const repositoryRoot = path.resolve(packageDir, "../..");
const tarballDir = path.resolve(args["tarball-dir"]);
const packJsonPath = path.resolve(args["pack-json"]);
const { packed, tarball } = resolveTarballPath({ packJsonPath, tarballDir });
const { packedFiles } = assertCustomerPackage({ packed, tarball });
const fixturePath = path.join(
  packageDir,
  "fixtures/receipt-v1/production-receipt-v1-bonk-verified.json",
);
const scratch = mkdtempSync(path.join(tmpdir(), "raven-release-tarball-test-"));
const consumerDir = path.join(scratch, "consumer");
const npm = npmCommand();
const tscCandidates = [
  path.join(packageDir, "node_modules", "typescript", "bin", "tsc"),
  path.join(repositoryRoot, "node_modules", "typescript", "bin", "tsc"),
];
const tsc = tscCandidates.find((candidate) => existsSync(candidate));

if (!tsc) {
  throw new Error(`typescript not found; looked in: ${tscCandidates.join(", ")}`);
}

try {
  run(npm, ["init", "--yes"], { cwd: scratch });
  run(npm, ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--offline", tarball], {
    cwd: scratch,
  });

  mkdirSync(consumerDir);
  copyFileSync(fixturePath, path.join(consumerDir, "receipt.json"));
  writeFileSync(
    path.join(consumerDir, "verify.mjs"),
    `import { readFileSync } from "node:fs";
import * as pkg from "raven-receipt-verifier";
import {
  RAVEN_PRODUCTION_TRUST_ANCHOR,
  ravenProductionTrustedKeys,
  verifyReceiptV1,
  verifyReceiptV1ForSubject,
} from "raven-receipt-verifier";

const vector = JSON.parse(readFileSync(new URL("./receipt.json", import.meta.url), "utf8"));
if (
  RAVEN_PRODUCTION_TRUST_ANCHOR.length !== 1 ||
  RAVEN_PRODUCTION_TRUST_ANCHOR[0].publicKeyBase64 !== vector.input.signerPublicKey
) {
  throw new Error("packed production trust anchor does not match the production receipt signer");
}
const mutated = ravenProductionTrustedKeys();
mutated.add("customer-added-key");
if (ravenProductionTrustedKeys().has("customer-added-key")) {
  throw new Error("packed production trust key helper leaked mutable state");
}
const opts = { now: vector.now, trustedKeys: ravenProductionTrustedKeys() };
const result = verifyReceiptV1(vector.input, opts);
if (!result.valid || !result.keyTrusted || result.stale) {
  throw new Error("packed verifier rejected the production receipt: " + JSON.stringify(result));
}
const subject = {
  chain: vector.input.chain,
  mintAddress: vector.input.mintAddress,
  tokenProgramAddress: vector.input.tokenProgramAddress,
};
const bound = verifyReceiptV1ForSubject(vector.input, subject, opts);
if (!bound.valid || !bound.keyTrusted || bound.subjectMatches !== true) {
  throw new Error("packed wrapper rejected the production subject: " + JSON.stringify(bound));
}
const mismatched = verifyReceiptV1ForSubject(
  vector.input,
  { ...subject, mintAddress: "So11111111111111111111111111111111111111112" },
  opts,
);
if (mismatched.subjectMatches !== false || mismatched.subjectReasons.join(",") !== "subject_mint_mismatch") {
  throw new Error("packed wrapper missed a mint mismatch: " + JSON.stringify(mismatched));
}
const noPolicy = verifyReceiptV1ForSubject(vector.input, subject, { now: vector.now });
if (noPolicy.keyTrusted !== false || !noPolicy.reasons.includes("trust_config_invalid")) {
  throw new Error("packed wrapper left the trust axis unevaluated: " + JSON.stringify(noPolicy));
}
if ("verifyReceiptEvmV1" in pkg || "verifyManifestChain" in pkg) {
  throw new Error("packed tarball publicly exports a PROPOSED API");
}
await import("raven-receipt-verifier/dist/verifyReceiptEvmV1.js").then(
  () => { throw new Error("PROPOSED subpath is reachable through the export map"); },
  () => {},
);
console.log(JSON.stringify({
  receiptId: vector.input.receiptId,
  valid: result.valid,
  keyTrusted: result.keyTrusted,
  stale: result.stale,
  subjectMatches: bound.subjectMatches,
}));
`,
    "utf8",
  );

  writeFileSync(
    path.join(consumerDir, "verify.cjs"),
    `const { readFileSync } = require("node:fs");
const {
  RAVEN_PRODUCTION_TRUST_ANCHOR,
  ravenProductionTrustedKeys,
  verifyReceiptV1,
} = require("raven-receipt-verifier");

const vector = JSON.parse(readFileSync(__dirname + "/receipt.json", "utf8"));
if (
  RAVEN_PRODUCTION_TRUST_ANCHOR.length !== 1 ||
  RAVEN_PRODUCTION_TRUST_ANCHOR[0].publicKeyBase64 !== vector.input.signerPublicKey
) {
  throw new Error("CJS require() consumer could not read the production trust anchor");
}
const result = verifyReceiptV1(vector.input, {
  now: vector.now,
  trustedKeys: ravenProductionTrustedKeys(),
});
if (!result.valid || !result.keyTrusted || result.stale) {
  throw new Error("CJS require() consumer rejected the production receipt: " + JSON.stringify(result));
}
console.log(JSON.stringify({ via: "require()", valid: result.valid, keyTrusted: result.keyTrusted, stale: result.stale }));
`,
    "utf8",
  );

  writeFileSync(
    path.join(scratch, "consumer.ts"),
    `import {
  RAVEN_PRODUCTION_TRUST_ANCHOR,
  ravenProductionTrustedKeys,
  verifyReceiptV1,
  verifyReceiptV1ForSubject,
  type ExpectedSolanaReceiptSubject,
  type RavenTrustAnchorKey,
  type VerifyReceiptForSubjectResult,
} from "raven-receipt-verifier";

const result = verifyReceiptV1({}, { now: "2026-01-01T00:00:00.000Z" });
const valid: boolean = result.valid;
const reasons: string[] = result.reasons;
void valid;
void reasons;
const anchors: readonly RavenTrustAnchorKey[] = RAVEN_PRODUCTION_TRUST_ANCHOR;
const keys: Set<string> = ravenProductionTrustedKeys();
void anchors;
void keys;

const subject: ExpectedSolanaReceiptSubject = {
  chain: "solana-mainnet",
  mintAddress: "So11111111111111111111111111111111111111112",
  tokenProgramAddress: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
};
const bound: VerifyReceiptForSubjectResult = verifyReceiptV1ForSubject(
  {},
  subject,
  { allowUntrustedKey: true },
);
const subjectMatches: boolean | null = bound.subjectMatches;
const subjectReasons: string[] = bound.subjectReasons;
const keyTrusted: boolean | undefined = bound.keyTrusted;
void subjectMatches;
void subjectReasons;
void keyTrusted;
`,
    "utf8",
  );
  writeFileSync(
    path.join(scratch, "tsconfig.json"),
    JSON.stringify(
      {
        compilerOptions: {
          target: "ES2022",
          module: "NodeNext",
          moduleResolution: "NodeNext",
          strict: true,
          noEmit: true,
          skipLibCheck: true,
          types: [],
        },
        include: ["consumer.ts"],
      },
      null,
      2,
    ),
    "utf8",
  );

  const noTypeStripping = process.allowedNodeEnvironmentFlags.has("--no-experimental-strip-types")
    ? ["--no-experimental-strip-types"]
    : [];
  const esm = run(process.execPath, [...noTypeStripping, "verify.mjs"], { cwd: consumerDir });
  const cjs = run(process.execPath, ["verify.cjs"], { cwd: consumerDir });
  run(process.execPath, [tsc, "-p", "tsconfig.json"], { cwd: scratch });
  const installedManifest = readJson(path.join(scratch, "node_modules/raven-receipt-verifier/package.json"));
  const installedSecurity = readFileSync(
    path.join(scratch, "node_modules/raven-receipt-verifier/SECURITY.md"),
    "utf8",
  );

  assert.ok(installedSecurity.includes("/.well-known/security.txt"));
  assert.equal(Object.keys(installedManifest.dependencies ?? {}).length, 0);

  console.log(`tarball: ${tarball}`);
  console.log(`package: ${packed.name}@${packed.version}`);
  console.log(`entry count: ${packed.entryCount}`);
  console.log(`packed size: ${packed.size}`);
  console.log(`unpacked size: ${packed.unpackedSize}`);
  console.log(`integrity: ${packed.integrity}`);
  console.log(`runtime dependencies: 0`);
  console.log(`packed files: ${packedFiles.join(", ")}`);
  console.log(`installed export: ${JSON.stringify(installedManifest.exports["."])}`);
  process.stdout.write(esm.stdout);
  process.stdout.write(cjs.stdout);
  console.log(`declaration consumer compiled against ${installedManifest.exports["."].types}`);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
