import { writeFileSync } from "node:fs";
import path from "node:path";

import {
  comparePackMetadataToActual,
  git,
  measureReleaseArtifact,
  npmCommand,
  parseArgs,
  run,
} from "./release-artifact-utils.mjs";
import { PINNED_NPM_VERSION } from "./release-policy.mjs";

const args = parseArgs(process.argv);
const measured = measureReleaseArtifact({
  packJsonPath: path.resolve(args["pack-json"]),
  tarballDir: path.resolve(args["tarball-dir"]),
});
comparePackMetadataToActual(measured);

const npmVersion = run(npmCommand(), ["--version"]);
if (npmVersion !== PINNED_NPM_VERSION) {
  throw new Error(`npm version expected ${PINNED_NPM_VERSION}, actual ${npmVersion}`);
}

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
    npm: npmVersion,
  },
};

writeFileSync(path.resolve(args.out), `${JSON.stringify(identity, null, 2)}\n`, "utf8");
console.log(`artifact handoff written: ${path.resolve(args.out)}`);
console.log(`actual tgz SHA-512: ${measured.actual.sha512}`);
