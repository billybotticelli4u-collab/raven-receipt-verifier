import path from "node:path";
import { pathToFileURL } from "node:url";

import {
  compareActualToFrozen,
  compareActualToHandoff,
  comparePackMetadataToActual,
  gitAt,
  measureReleaseArtifact,
  parseArgs,
  readJson,
} from "./release-artifact-utils.mjs";
import {
  NODE_FLOOR,
  PACKAGE_NAME,
  PACKAGE_VERSION,
  PINNED_NPM_VERSION,
  PUBLIC_MIRROR_PACKAGE_TREE,
  PUBLIC_REPOSITORY,
  PUBLICATION_REF,
  UPSTREAM_ACCEPTED_COMMIT,
  UPSTREAM_ACCEPTED_PACKAGE_TREE,
  UPSTREAM_ACCEPTED_TREE,
} from "./release-policy.mjs";

const same = (failures, label, expected, actual) => {
  if (expected !== actual) failures.push(`${label}: expected ${expected}, actual ${actual}`);
};

const sameJson = (failures, label, expected, actual) => {
  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    failures.push(`${label}: expected ${JSON.stringify(expected)}, actual ${JSON.stringify(actual)}`);
  }
};

export const verifyReleaseArtifact = ({
  packJsonPath,
  tarballDir,
  artifactIdentityPath,
  frozenIdentityPath,
  confirmVersion,
  releaseRef,
  releaseSha,
  releaseTree,
  cwd = process.cwd(),
}) => {
  const frozen = readJson(path.resolve(frozenIdentityPath));
  const handoff = readJson(path.resolve(artifactIdentityPath));
  const measured = measureReleaseArtifact({ packJsonPath, tarballDir });
  comparePackMetadataToActual(measured);
  compareActualToFrozen({ actual: measured.actual, frozenArtifact: frozen.artifact });
  compareActualToHandoff({ actual: measured.actual, handoff });

  const failures = [];
  same(failures, "release identity schema", "raven-receipt-verifier-release-identity/2", frozen.schema);
  same(failures, "package name", PACKAGE_NAME, frozen.package.name);
  same(failures, "package version", PACKAGE_VERSION, frozen.package.version);
  same(failures, "confirm version", PACKAGE_VERSION, confirmVersion);
  same(failures, "Node floor", NODE_FLOOR, frozen.package.nodeFloor);
  same(failures, "runtime dependency count", 0, frozen.package.runtimeDependencies);
  sameJson(failures, "frozen export map", measured.manifest.exports, frozen.package.exportMap);
  same(failures, "frozen npm toolchain", PINNED_NPM_VERSION, frozen.toolchain?.npm);
  sameJson(failures, "frozen Node executions", ["v22.18.0", "v24.20.0"], frozen.toolchain?.nodeExecutions);
  same(failures, "upstream commit", UPSTREAM_ACCEPTED_COMMIT, frozen.upstreamSource.commit);
  same(failures, "upstream tree", UPSTREAM_ACCEPTED_TREE, frozen.upstreamSource.tree);
  same(failures, "upstream package tree", UPSTREAM_ACCEPTED_PACKAGE_TREE, frozen.upstreamSource.packageTree);
  same(failures, "public repository", PUBLIC_REPOSITORY.replace(/^git\+/, "").replace(/\.git$/, ""), frozen.publicMirror.repository);
  same(failures, "public package directory", "packages/verify-js", frozen.publicMirror.packageDirectory);
  same(failures, "public package tree", PUBLIC_MIRROR_PACKAGE_TREE, frozen.publicMirror.packageTree);
  same(failures, "publication ref policy", PUBLICATION_REF, frozen.publicMirror.publicationRef);
  same(failures, "public commit binding", "RAVEN_RELEASE_SHA == GITHUB_SHA == HEAD == freshly-resolved publicationRef^{commit}", frozen.publicMirror.commitBinding);
  same(failures, "public tree binding", "RAVEN_RELEASE_TREE == HEAD^{tree} == freshly-resolved publicationRef^{commit}^{tree}", frozen.publicMirror.treeBinding);
  same(failures, "release ref", PUBLICATION_REF, releaseRef);
  same(failures, "handoff ref", releaseRef, handoff.source?.ref);
  same(failures, "handoff commit", releaseSha, handoff.source?.commit);
  same(failures, "handoff tree", releaseTree, handoff.source?.tree);
  same(failures, "checked-out commit", releaseSha, gitAt(cwd, "rev-parse", "HEAD"));
  same(failures, "checked-out tree", releaseTree, gitAt(cwd, "rev-parse", "HEAD^{tree}"));
  same(failures, "handoff npm", PINNED_NPM_VERSION, handoff.toolchain?.npm);
  if (!/^v(?:22\.18\.0|24\.[0-9]+\.[0-9]+)$/.test(handoff.toolchain?.node ?? "")) {
    failures.push(`handoff Node version is not governed: ${handoff.toolchain?.node ?? "<missing>"}`);
  }
  if (failures.length) throw new Error(failures.join("\n"));
  return measured;
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = parseArgs(process.argv);
    const measured = verifyReleaseArtifact({
      packJsonPath: path.resolve(args["pack-json"]),
      tarballDir: path.resolve(args["tarball-dir"]),
      artifactIdentityPath: path.resolve(args["artifact-identity"]),
      frozenIdentityPath: path.resolve(args["frozen-identity"]),
      confirmVersion: args["confirm-version"],
      releaseRef: args["release-ref"],
      releaseSha: args["release-sha"],
      releaseTree: args["release-tree"],
    });
    console.log("actual tarball matches frozen authorization and immutable source handoff");
    console.log(`tarball: ${measured.tarball}`);
    console.log(`actual tgz SHA-512: ${measured.actual.sha512}`);
  } catch (error) {
    console.error(`REFUSED release artifact: ${error.message}`);
    process.exit(1);
  }
}
