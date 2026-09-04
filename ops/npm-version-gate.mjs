// Fail-closed guard for Raven's npm publication toolchain. The release
// workflow installs one exact npm CLI and every publication-critical job must
// prove that `npm --version` resolves to that value before it can pack, verify,
// or publish an artifact.
import { spawnSync } from "node:child_process";

const expected = process.argv[2] ?? process.env.RAVEN_EXPECTED_NPM_VERSION;

if (!expected) {
  console.error("REFUSED npm version: expected version was not supplied");
  process.exit(1);
}

const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const result = spawnSync(npm, ["--version"], { encoding: "utf8" });

if (result.error) {
  console.error(`REFUSED npm version: ${result.error.message}`);
  process.exit(1);
}

if (result.status !== 0) {
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  console.error(`REFUSED npm version: npm --version exited ${result.status}`);
  process.exit(result.status ?? 1);
}

const actual = result.stdout.trim();
if (actual !== expected) {
  console.error(`REFUSED npm version: expected ${expected}, actual ${actual}`);
  process.exit(1);
}

console.log(`npm version ${actual} matches expected ${expected}`);
