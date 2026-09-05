import { spawnSync } from "node:child_process";

import { assertGovernedNodeLine, verifyGovernedNpm } from "./governed-npm.mjs";
import { parseArgs } from "./release-artifact-utils.mjs";
import { GOVERNED_NPM, PINNED_NPM_VERSION } from "./release-policy.mjs";

// Byte identity first; the printed version is a sanity assertion only, and it
// is produced by the governed Node running the byte-verified CLI — never by a
// PATH-resolved program.
try {
  const args = parseArgs(process.argv);
  if (!args["governed-npm"]) throw new Error("usage: npm-version-gate --governed-npm <package dir>");
  if (GOVERNED_NPM.version !== PINNED_NPM_VERSION) throw new Error("policy npm artifact version disagrees with pinned version");
  assertGovernedNodeLine();
  const identity = verifyGovernedNpm(args["governed-npm"]);
  const reported = spawnSync(process.execPath, [identity.cli, "--version"], { encoding: "utf8" });
  if (reported.status !== 0 || reported.stdout.trim() !== PINNED_NPM_VERSION) {
    throw new Error(`governed npm reports ${reported.stdout.trim() || "nothing"}, expected ${PINNED_NPM_VERSION}`);
  }
  console.log(`governed npm ${identity.version} verified by bytes (tree ${identity.treeSha256.slice(0, 16)}…) under ${process.version}`);
} catch (error) {
  console.error(`REFUSED npm: ${error.message}`);
  process.exit(1);
}
