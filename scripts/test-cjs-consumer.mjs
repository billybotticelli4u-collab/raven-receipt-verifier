// Release gate: the packed tarball must be loadable from a CommonJS consumer
// via require(esm) on the declared Node floor (>=22.18). Deliberate ESM-only
// packaging means this script is the only proof that CJS consumers are served.
import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
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
const scratch = mkdtempSync(path.join(tmpdir(), "raven-receipt-verifier-cjs-"));
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

  run(npm, ["init", "--yes"], { cwd: scratch });
  run(npm, ["install", "--ignore-scripts", "--no-audit", "--no-fund", "--offline", tarball], {
    cwd: scratch,
  });

  mkdirSync(consumerDir);
  copyFileSync(fixturePath, path.join(consumerDir, "receipt.json"));
  // A .cjs file is unambiguous CommonJS regardless of any package.json type.
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

  const verification = run(process.execPath, ["verify.cjs"], { cwd: consumerDir });
  console.log(`tarball: ${tarball}`);
  console.log(`node: ${process.version}`);
  process.stdout.write(verification.stdout);
} finally {
  if (process.env.KEEP_VERIFY_JS_PACK_TMP !== "1") {
    rmSync(scratch, { recursive: true, force: true });
  } else {
    console.log(`kept temp directory: ${scratch}`);
  }
}
