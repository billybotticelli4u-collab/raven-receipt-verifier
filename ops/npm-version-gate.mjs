import { spawnSync } from "node:child_process";

import { PINNED_NPM_VERSION } from "./release-policy.mjs";

const expected = process.argv[2] ?? PINNED_NPM_VERSION;
const npm = process.platform === "win32" ? "npm.cmd" : "npm";
const result = spawnSync(npm, ["--version"], { encoding: "utf8" });
const actual = result.stdout.trim();

if (result.status !== 0 || expected !== PINNED_NPM_VERSION || actual !== PINNED_NPM_VERSION) {
  console.error(`REFUSED npm version: policy ${PINNED_NPM_VERSION}, expected ${expected}, actual ${actual || "unavailable"}`);
  process.exit(1);
}
console.log(`npm version ${actual} matches publication policy`);
