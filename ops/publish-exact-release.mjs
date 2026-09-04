import { spawnSync } from "node:child_process";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { npmCommand, parseArgs, run } from "./release-artifact-utils.mjs";
import { PINNED_NPM_VERSION } from "./release-policy.mjs";
import { verifyReleaseArtifact } from "./verify-release-artifact.mjs";
import { verifyReleaseRef } from "./verify-release-ref.mjs";

const defaultPublisher = (tarball) => {
  const result = spawnSync(npmCommand(), ["publish", tarball, "--provenance", "--access", "public"], {
    stdio: "inherit",
  });
  if (result.status !== 0) throw new Error(`npm publish exited ${result.status}`);
};

export const guardAndPublish = ({
  packJsonPath,
  tarballDir,
  artifactIdentityPath,
  frozenIdentityPath,
  confirmVersion,
  releaseRef,
  releaseSha,
  releaseTree,
  githubRef,
  githubSha,
  remote = "origin",
  cwd = process.cwd(),
  publisher = defaultPublisher,
}) => {
  const actualNpm = run(npmCommand(), ["--version"]);
  if (actualNpm !== PINNED_NPM_VERSION) {
    throw new Error(`npm version expected ${PINNED_NPM_VERSION}, actual ${actualNpm}`);
  }
  verifyReleaseRef({
    releaseRef,
    releaseSha,
    releaseTree,
    githubRef,
    githubSha,
    remote,
    cwd,
  });
  const measured = verifyReleaseArtifact({
    packJsonPath,
    tarballDir,
    artifactIdentityPath,
    frozenIdentityPath,
    confirmVersion,
    releaseRef,
    releaseSha,
    releaseTree,
    cwd,
  });

  // There is intentionally no callback or workflow boundary between this
  // measurement and the publish invocation. npm receives the exact path that
  // measureReleaseArtifact opened and hashed above.
  publisher(measured.tarball);
  return { tarball: measured.tarball, actual: measured.actual };
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const args = parseArgs(process.argv);
    const result = guardAndPublish({
      packJsonPath: path.resolve(args["pack-json"]),
      tarballDir: path.resolve(args["tarball-dir"]),
      artifactIdentityPath: path.resolve(args["artifact-identity"]),
      frozenIdentityPath: path.resolve(args["frozen-identity"]),
      confirmVersion: args["confirm-version"],
      releaseRef: process.env.RAVEN_RELEASE_REF,
      releaseSha: process.env.RAVEN_RELEASE_SHA,
      releaseTree: process.env.RAVEN_RELEASE_TREE,
      githubRef: process.env.GITHUB_REF,
      githubSha: process.env.GITHUB_SHA,
      remote: process.env.RAVEN_RELEASE_REMOTE ?? "origin",
    });
    console.log(`published exact verified tarball: ${result.tarball}`);
  } catch (error) {
    console.error(`REFUSED publication: ${error.message}`);
    process.exit(1);
  }
}
