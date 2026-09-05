import { writeFileSync } from "node:fs";
import path from "node:path";

import { governedNodeIdentity, verifyGovernedNpm } from "./governed-npm.mjs";
import {
  comparePackMetadataToActual,
  git,
  measureReleaseArtifact,
  parseArgs,
} from "./release-artifact-utils.mjs";
import { PINNED_NPM_VERSION } from "./release-policy.mjs";

const args = parseArgs(process.argv);
const measured = measureReleaseArtifact({
  packJsonPath: path.resolve(args["pack-json"]),
  tarballDir: path.resolve(args["tarball-dir"]),
});
comparePackMetadataToActual(measured);

if (!args["governed-npm"]) throw new Error("--governed-npm <package dir> is required");
const governed = verifyGovernedNpm(args["governed-npm"]);
if (governed.version !== PINNED_NPM_VERSION) throw new Error(`governed npm ${governed.version} != pinned ${PINNED_NPM_VERSION}`);
const npmVersion = governed.version;

const identity = {
  schema: "raven-receipt-verifier-artifact-handoff/2",
  note: "Measured handoff evidence only. The committed frozen release identity remains the authorization oracle.",
  artifact: measured.actual,
  source: {
    commit: git("rev-parse", "HEAD"),
    tree: git("rev-parse", "HEAD^{tree}"),
    ref: process.env.GITHUB_REF ?? args["release-ref"] ?? null,
  },
  toolchain: {
    node: process.version,
    nodeExecPathSha256: governedNodeIdentity().execPathSha256,
    npm: npmVersion,
    npmArtifact: { cliSha256: governed.cliSha256, treeSha256: governed.treeSha256, fileCount: governed.fileCount },
  },
};

writeFileSync(path.resolve(args.out), `${JSON.stringify(identity, null, 2)}\n`, "utf8");
console.log(`artifact handoff written: ${path.resolve(args.out)}`);
console.log(`actual tgz SHA-512: ${measured.actual.sha512}`);
