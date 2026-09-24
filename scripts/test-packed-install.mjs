import assert from "node:assert/strict";
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const packageDir = fileURLToPath(new URL("..", import.meta.url));
const fixturePath = path.join(
  packageDir,
  "fixtures/receipt-v1/production-receipt-v1-bonk-verified.json",
);
const scratch = mkdtempSync(path.join(tmpdir(), "raven-receipt-verifier-pack-"));
const consumerDir = path.join(scratch, "consumer");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${command} ${args.join(" ")} exited ${result.status}`);
  }
  return result;
};

try {
  const packed = run(
    npm,
    ["pack", "--json", "--pack-destination", scratch],
    { cwd: packageDir },
  );
  const packResult = JSON.parse(packed.stdout);
  const tarball = path.join(scratch, packResult[0].filename);
  const packedFiles = packResult[0].files.map(({ path: packedPath }) => packedPath);
  const customerModules = [
    "canonicalDataSnapshot",
    "canonicalJson",
    "detect",
    "ed25519KeyDomain",
    "ed25519NodeVerify",
    "index",
    "outcomeProjection",
    "receiptRules",
    "receiptV1",
    "solanaAddress",
    "trustAnchor",
    "verifyReceiptV1",
    "verifyReceiptV1ForSubject",
  ];
  const compiledExtensions = [".d.ts", ".d.ts.map", ".js", ".js.map"];
  const expectedPackedFiles = [
    "LICENSE",
    "README.md",
    "SECURITY.md",
    "package.json",
    ...customerModules.flatMap((moduleName) =>
      compiledExtensions.map((extension) => `dist/${moduleName}${extension}`),
    ),
  ].sort();
  assert.deepEqual(
    [...packedFiles].sort(),
    expectedPackedFiles,
    "customer tarball must contain only the frozen Solana receipt-v1 runtime closure",
  );
  for (const required of [
    "dist/index.js",
    "dist/index.d.ts",
    "package.json",
    "README.md",
    "LICENSE",
  ]) {
    if (!packedFiles.includes(required)) {
      throw new Error(`packed tarball is missing ${required}`);
    }
  }
  if (packedFiles.some((packedPath) => packedPath.startsWith("src/"))) {
    throw new Error("packed tarball must not expose raw TypeScript sources");
  }

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

// The partner-facing wrapper must bind the exact signed subject tuple.
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
if (noPolicy.keyTrusted !== false || !noPolicy.reasons.includes("trust_config_missing")) {
  throw new Error("packed wrapper omit-path must report trust_config_missing: " + JSON.stringify(noPolicy));
}

// The PROPOSED EVM / key-manifest surface must stay out of the public map:
// absent from the namespace object AND unreachable as a package subpath.
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

  const installedManifest = JSON.parse(
    readFileSync(path.join(scratch, "node_modules/raven-receipt-verifier/package.json"), "utf8"),
  );
  // The packed SECURITY.md forbids public disclosure, so the private route it
  // names must be the durable RFC 9116 one — assert this from the INSTALLED
  // bytes, not the repository file.
  const installedSecurity = readFileSync(
    path.join(scratch, "node_modules/raven-receipt-verifier/SECURITY.md"),
    "utf8",
  );
  if (!installedSecurity.includes("/.well-known/security.txt")) {
    throw new Error("packed SECURITY.md does not name the durable RFC 9116 reporting route");
  }
  const runtimeDependencies = Object.keys(installedManifest.dependencies ?? {});
  if (runtimeDependencies.length !== 0) {
    throw new Error(`packed verifier must have zero runtime dependencies; got ${runtimeDependencies.join(", ")}`);
  }
  const noTypeStripping = process.allowedNodeEnvironmentFlags.has(
    "--no-experimental-strip-types",
  )
    ? ["--no-experimental-strip-types"]
    : [];
  const verification = run(
    process.execPath,
    [...noTypeStripping, "verify.mjs"],
    { cwd: consumerDir },
  );

  console.log(`tarball: ${tarball}`);
  console.log(`package: ${packResult[0].name}@${packResult[0].version}`);
  console.log(`entry count: ${packResult[0].entryCount}`);
  console.log(`packed size: ${packResult[0].size}`);
  console.log(`unpacked size: ${packResult[0].unpackedSize}`);
  console.log(`integrity: ${packResult[0].integrity}`);
  console.log(`runtime dependencies: ${runtimeDependencies.length}`);
  console.log(`packed files: ${packedFiles.join(", ")}`);
  console.log(`installed export: ${JSON.stringify(installedManifest.exports["."])}`);
  console.log(
    noTypeStripping.length === 0
      ? "type stripping: unavailable in this runtime (therefore disabled)"
      : "type stripping: explicitly disabled",
  );
  process.stdout.write(verification.stdout);
} finally {
  if (process.env.KEEP_VERIFY_JS_PACK_TMP !== "1") {
    rmSync(scratch, { recursive: true, force: true });
  } else {
    console.log(`kept temp directory: ${scratch}`);
  }
}
