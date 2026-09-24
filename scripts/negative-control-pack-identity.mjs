#!/usr/bin/env node
/**
 * Negative control for pack-identity binding:
 * 1) Measure decoded-tar SHA-256 of current tree
 * 2) Mutate package.json (temporary marker)
 * 3) Re-measure; require mismatch
 * 4) Restore original bytes
 * 5) Re-measure; require match to step 1
 * Never publishes. Restores even on failure.
 */
import { spawnSync } from "node:child_process";
import {
  createHash,
  randomBytes,
} from "node:crypto";
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  rmSync,
  copyFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const pkgPath = join(root, "package.json");
const EXPECTED =
  process.env.EXPECTED_DECODED_TAR_SHA256 ||
  "6764b02da729d502b6b3cb0072366fe0cb23ab46829d4b53e3afecb99bd63520";

function decodedTarSha256() {
  const scratch = mkdtempSync(join(tmpdir(), "rrv-neg-"));
  try {
    const pack = spawnSync("npm", ["pack", "--pack-destination", scratch], {
      cwd: root,
      encoding: "utf8",
    });
    if (pack.status !== 0) {
      throw new Error(`npm pack failed: ${pack.stderr || pack.stdout}`);
    }
    const tgz = join(scratch, "raven-receipt-verifier-0.1.0.tgz");
    const packed = readFileSync(tgz);
    const decoded = gunzipSync(packed);
    return createHash("sha256").update(decoded).digest("hex");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

const original = readFileSync(pkgPath);
const backup = original;
let mutated = false;
try {
  const d0 = decodedTarSha256();
  console.log(JSON.stringify({ step: "baseline", decoded_tar_sha256: d0 }));
  if (d0 !== EXPECTED) {
    console.error(
      `BASELINE_MISMATCH expected=${EXPECTED} got=${d0}`,
    );
    process.exit(2);
  }

  const pkg = JSON.parse(original.toString("utf8"));
  pkg.__negative_control_marker = randomBytes(8).toString("hex");
  writeFileSync(pkgPath, JSON.stringify(pkg, null, 2) + "\n");
  mutated = true;

  const d1 = decodedTarSha256();
  console.log(
    JSON.stringify({
      step: "mutated",
      decoded_tar_sha256: d1,
      differs: d1 !== d0,
    }),
  );
  if (d1 === d0) {
    console.error("NEGATIVE_CONTROL_FAILED: mutation did not change decoded-tar");
    process.exit(3);
  }

  writeFileSync(pkgPath, backup);
  mutated = false;

  const d2 = decodedTarSha256();
  console.log(
    JSON.stringify({
      step: "restored",
      decoded_tar_sha256: d2,
      matches_baseline: d2 === d0,
    }),
  );
  if (d2 !== d0) {
    console.error("RESTORE_MISMATCH");
    process.exit(4);
  }
  console.log(
    JSON.stringify({
      pass: true,
      expected_decoded_tar_sha256: EXPECTED,
      baseline: d0,
      mutated: d1,
      restored: d2,
    }),
  );
} finally {
  if (mutated) {
    writeFileSync(pkgPath, backup);
    console.error("restored package.json after failure path");
  }
}
