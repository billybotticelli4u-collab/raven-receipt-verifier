import { appendFileSync, chmodSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

import { governedNodeIdentity, verifyGovernedNpm, verifyGovernedNpmTarball } from "./governed-npm.mjs";
import { parseArgs } from "./release-artifact-utils.mjs";

// Verify the downloaded npm registry artifact by bytes, extract it, verify
// the extracted tree by bytes, and expose a shim so non-publication steps
// resolve `npm` to the governed CLI. The publication boundary never uses the
// shim or PATH; it invokes the verified CLI by absolute path.
const args = parseArgs(process.argv);
const tarball = path.resolve(args.tarball);
const dest = path.resolve(args.dest);
const tarballIdentity = verifyGovernedNpmTarball(tarball);
rmSync(dest, { recursive: true, force: true });
mkdirSync(dest, { recursive: true });
const extracted = spawnSync("/usr/bin/tar", ["-xzf", tarball, "-C", dest], { encoding: "utf8" });
if (extracted.status !== 0) throw new Error(`governed npm extraction failed: ${extracted.stderr}`);
const packageDir = path.join(dest, "package");
const identity = verifyGovernedNpm(packageDir);
const node = governedNodeIdentity();
mkdirSync(path.join(dest, "bin"), { recursive: true });
const shim = path.join(dest, "bin", "npm");
writeFileSync(shim, `#!/bin/sh\nexec ${JSON.stringify(node.execPath)} ${JSON.stringify(identity.cli)} "$@"\n`);
chmodSync(shim, 0o755);
if (process.env.GITHUB_PATH) appendFileSync(process.env.GITHUB_PATH, `${path.join(dest, "bin")}\n`);
console.log(JSON.stringify({ governedNpm: { ...identity, tarball: tarballIdentity }, governedNode: node }, null, 2));
