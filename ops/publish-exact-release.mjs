import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { npmCommand, parseArgs, run } from "./release-artifact-utils.mjs";
import { CANONICAL_TARBALL, PINNED_NPM_VERSION, PUBLICATION_REGISTRY, WORKFLOW_PATH, WORKFLOW_SHA256 } from "./release-policy.mjs";
import { verifyReleaseArtifact } from "./verify-release-artifact.mjs";
import { verifyReleaseRef } from "./verify-release-ref.mjs";

const sha512 = (bytes) => createHash("sha512").update(bytes).digest("hex");

const defaultPublisher = (tarball) => {
  const result = spawnSync(npmCommand(), [
    "publish", tarball, "--provenance", "--access", "public", "--registry", PUBLICATION_REGISTRY,
  ], { stdio: "inherit" });
  if (result.status !== 0) throw new Error(`npm publish exited ${result.status}`);
};

// The workflow that dispatched this process is the one at HEAD (ref gate).
// Refuse unless those exact bytes are the policy-pinned workflow, so a
// workflow edit can never publish without a matching, reviewed policy edit.
export const assertPinnedWorkflow = (cwd) => {
  let bytes;
  try { bytes = readFileSync(path.join(cwd, WORKFLOW_PATH)); }
  catch { throw new Error(`checked-out workflow ${WORKFLOW_PATH} is missing; refusing to publish`); }
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== WORKFLOW_SHA256) throw new Error(`checked-out workflow sha256 ${actual} is not the policy-pinned workflow ${WORKFLOW_SHA256}`);
};

const assertPinnedRegistry = () => {
  const resolved = run(npmCommand(), ["config", "get", "registry"]).replace(/\/+$/, "");
  if (resolved !== PUBLICATION_REGISTRY) {
    throw new Error(`npm resolves registry ${resolved}, policy requires ${PUBLICATION_REGISTRY}`);
  }
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
  // Test seam only: runs after sealing, before the boundary re-check. Inert
  // by default; the workflow has no way to supply it.
  beforePublish = () => {},
}) => {
  const actualNpm = run(npmCommand(), ["--version"]);
  if (actualNpm !== PINNED_NPM_VERSION) {
    throw new Error(`npm version expected ${PINNED_NPM_VERSION}, actual ${actualNpm}`);
  }
  assertPinnedRegistry();
  verifyReleaseRef({ releaseRef, releaseSha, releaseTree, githubRef, githubSha, remote, cwd });
  assertPinnedWorkflow(cwd);
  const measured = verifyReleaseArtifact({
    packJsonPath, tarballDir, artifactIdentityPath, frozenIdentityPath,
    confirmVersion, releaseRef, releaseSha, releaseTree, cwd,
  });

  // Seal the exact bytes that were just authenticated into a private,
  // process-owned copy. npm is handed the sealed copy, never the shared
  // artifact path, so nothing that can reach that path after verification
  // can reach the registry. The sealed bytes come from the in-memory buffer
  // measureReleaseArtifact hashed — not from a second read of the shared file.
  const expectedSha512 = measured.actual.sha512;
  if (sha512(measured.bytes) !== expectedSha512) throw new Error("sealed bytes do not match the authenticated identity");
  const sealDir = mkdtempSync(path.join(tmpdir(), "raven-sealed-release-"), { mode: 0o700 });
  const sealed = path.join(sealDir, CANONICAL_TARBALL);
  try {
    writeFileSync(sealed, measured.bytes, { mode: 0o400, flag: "wx" });
    chmodSync(sealed, 0o400);
    beforePublish(sealed);
    // Boundary re-check: the sealed copy is re-read and re-hashed immediately
    // before npm opens it. No callback, step or shell boundary sits between
    // this check and the publish call.
    if (sha512(readFileSync(sealed)) !== expectedSha512) {
      throw new Error("sealed tarball changed before publication; refusing to publish");
    }
    publisher(sealed);
    if (sha512(readFileSync(sealed)) !== expectedSha512) {
      throw new Error("sealed tarball changed during publication; published bytes are UNCERTAIN — treat this release as compromised");
    }
  } finally {
    try { chmodSync(sealed, 0o600); } catch {}
    rmSync(sealDir, { recursive: true, force: true });
  }
  return { tarball: measured.tarball, sealed, sealedSha256: measured.actual.sha256, actual: measured.actual };
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
    console.log(`published exact verified tarball: ${result.tarball} (sealed copy sha256 ${result.sealedSha256})`);
  } catch (error) {
    console.error(`REFUSED publication: ${error.message}`);
    process.exit(1);
  }
}
