import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { chmodSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { assertGovernedNodeLine, governedNodeIdentity, sealGovernedNpmExecution, verifyGovernedNpm } from "./governed-npm.mjs";
import { parseArgs } from "./release-artifact-utils.mjs";
import {
  CANONICAL_TARBALL,
  PUBLICATION_REGISTRY,
  PUBLISH_ENV_FORBIDDEN,
  PUBLISH_ENV_PASSTHROUGH,
  WORKFLOW_PATH,
  WORKFLOW_SHA256,
} from "./release-policy.mjs";
import { verifyReleaseArtifact } from "./verify-release-artifact.mjs";
import { verifyReleaseRef } from "./verify-release-ref.mjs";

const sha512 = (bytes) => createHash("sha512").update(bytes).digest("hex");
const sha1 = (bytes) => createHash("sha1").update(bytes).digest("hex");

// The workflow that dispatched this process is the one at HEAD (ref gate).
// Refuse unless those exact bytes are the policy-pinned workflow.
export const assertPinnedWorkflow = (cwd) => {
  let bytes;
  try { bytes = readFileSync(path.join(cwd, WORKFLOW_PATH)); }
  catch { throw new Error(`checked-out workflow ${WORKFLOW_PATH} is missing; refusing to publish`); }
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== WORKFLOW_SHA256) throw new Error(`checked-out workflow sha256 ${actual} is not the policy-pinned workflow ${WORKFLOW_SHA256}`);
};

// Fail closed: an inherited environment that carries any override channel is
// not the reviewed runner. Nothing is silently stripped from these classes.
export const assertNoForbiddenEnvironment = (inherited) => {
  const offending = Object.keys(inherited).filter((name) => PUBLISH_ENV_FORBIDDEN.some((pattern) => pattern.test(name)));
  if (offending.length) throw new Error(`publish environment carries forbidden variables: ${offending.sort().join(", ")}`);
};

// Construct — never inherit — the publisher's environment.
export const buildPublishEnvironment = ({ inherited, home, tmp, nodeBinDir }) => {
  const env = {
    PATH: [nodeBinDir, "/usr/bin", "/bin"].join(path.delimiter),
    HOME: home,
    TMPDIR: tmp,
    TMP: tmp,
    TEMP: tmp,
  };
  for (const name of PUBLISH_ENV_PASSTHROUGH) {
    if (Object.hasOwn(inherited, name) && inherited[name] !== undefined) env[name] = inherited[name];
  }
  return env;
};

const parsePublishNotices = (stdout) => {
  const pick = (label) => (stdout.match(new RegExp(`npm notice ${label}:\\s*(\\S+)`)) ?? [])[1] ?? null;
  const registry = (stdout.match(/Publishing to (\S+?)\/? with/) ?? [])[1] ?? null;
  return { shasum: pick("shasum"), integrity: pick("integrity"), totalFiles: pick("total files"), registry };
};

// The only publisher: the governed Node (this process's runtime, already
// asserted to be a governed line) executing the byte-verified npm CLI by
// absolute path, inside a constructed environment, with every configuration
// source pinned by flag. PATH resolution is never consulted.
const governedPublisher = ({ cli, sealed, sealDir, env, dryRun }) => {
  const userconfig = path.join(sealDir, "governed-userconfig");
  const globalconfig = path.join(sealDir, "governed-globalconfig");
  writeFileSync(userconfig, "", { mode: 0o400 });
  writeFileSync(globalconfig, "", { mode: 0o400 });
  const args = [
    cli, "publish", sealed,
    "--provenance", "--access", "public",
    "--registry", `${PUBLICATION_REGISTRY}/`,
    "--userconfig", userconfig,
    "--globalconfig", globalconfig,
    "--ignore-scripts", "--no-fund", "--no-audit",
    ...(dryRun ? ["--dry-run"] : []),
  ];
  const result = spawnSync(process.execPath, args, { cwd: sealDir, env, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  process.stdout.write(result.stdout ?? "");
  process.stderr.write(result.stderr ?? "");
  if (result.status !== 0) throw new Error(`governed npm publish exited ${result.status}`);
  return parsePublishNotices(`${result.stdout}\n${result.stderr}`);
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
  governedNpmDir,
  remote = "origin",
  cwd = process.cwd(),
  inheritedEnvironment = process.env,
  dryRun = false,
  publisher = null,
  // Test seam only: runs after sealing, before the boundary re-checks. Inert
  // by default; the workflow has no way to supply it.
  beforePublish = () => {},
}) => {
  if (!governedNpmDir) throw new Error("governed npm package directory is required; PATH npm is never used");
  assertGovernedNodeLine();
  assertNoForbiddenEnvironment(inheritedEnvironment);
  const sourceGoverned = verifyGovernedNpm(governedNpmDir);
  verifyReleaseRef({ releaseRef, releaseSha, releaseTree, githubRef, githubSha, remote, cwd });
  assertPinnedWorkflow(cwd);
  const measured = verifyReleaseArtifact({
    packJsonPath, tarballDir, artifactIdentityPath, frozenIdentityPath,
    confirmVersion, releaseRef, releaseSha, releaseTree, cwd,
  });

  const expectedSha512 = measured.actual.sha512;
  if (sha512(measured.bytes) !== expectedSha512) throw new Error("sealed bytes do not match the authenticated identity");
  const sealRoot = mkdtempSync(path.join(tmpdir(), "raven-sealed-release-"), { mode: 0o700 });
  const sealDir = path.join(sealRoot, "artifact");
  const home = path.join(sealRoot, "home");
  const tmp = path.join(sealRoot, "tmp");
  for (const dir of [sealDir, home, tmp]) mkdirSync(dir, { mode: 0o700 });
  const sealed = path.join(sealDir, CANONICAL_TARBALL);
  try {
    // Seal as late as possible: the exact in-memory bytes that were hashed.
    writeFileSync(sealed, measured.bytes, { mode: 0o400, flag: "wx" });
    chmodSync(sealed, 0o400);
    const governed = sealGovernedNpmExecution(sourceGoverned.packageDir, sealRoot);
    beforePublish(sealed, governed);
    // Boundary re-checks, immediately before the governed CLI is executed:
    // the sealed bytes AND the npm tree that will read them.
    if (sha512(readFileSync(sealed)) !== expectedSha512) throw new Error("sealed tarball changed before publication; refusing to publish");
    const late = verifyGovernedNpm(governed.packageDir);
    if (late.treeSha256 !== governed.treeSha256 || late.cli !== governed.cli) throw new Error("governed npm changed before publication; refusing to publish");
    if (!governed.cli.startsWith(governed.execRoot + path.sep)) throw new Error("publication CLI outside execution seal");
    const env = buildPublishEnvironment({ inherited: inheritedEnvironment, home, tmp, nodeBinDir: path.dirname(process.execPath) });
    const observed = publisher
      ? publisher(sealed, { cli: governed.cli, env, sealDir, execRoot: governed.execRoot, sourcePackageDir: governed.sourcePackageDir })
      : governedPublisher({ cli: governed.cli, sealed, sealDir, env, dryRun });
    if (observed && observed.shasum && observed.shasum !== sha1(measured.bytes)) throw new Error(`governed npm observed shasum ${observed.shasum}, not the frozen ${sha1(measured.bytes)}; published bytes are UNCERTAIN`);
    if (observed && observed.integrity && observed.integrity !== measured.actual.integrity && !measured.actual.integrity.startsWith(observed.integrity.replace(/\[\.\.\.\].*$/, ""))) throw new Error("governed npm observed a different integrity; published bytes are UNCERTAIN");
    if (observed && observed.registry && observed.registry.replace(/\/+$/, "") !== PUBLICATION_REGISTRY) throw new Error(`governed npm published to ${observed.registry}, not ${PUBLICATION_REGISTRY}`);
    if (sha512(readFileSync(sealed)) !== expectedSha512) throw new Error("sealed tarball changed during publication; published bytes are UNCERTAIN — treat this release as compromised");
    return {
      tarball: measured.tarball, sealed, sealedSha256: measured.actual.sha256, actual: measured.actual,
      governedNpm: governed, governedNode: governedNodeIdentity(), observed, environment: Object.keys(env).sort(),
    };
  } finally {
    try { chmodSync(sealed, 0o600); } catch {}
    try {
      // Owner must regain write bits to destroy a 0500/0400 execution seal.
      const unlock = (dir) => {
        try { chmodSync(dir, 0o700); } catch { return; }
        for (const name of readdirSync(dir)) {
          const full = path.join(dir, name);
          try {
            const st = lstatSync(full);
            if (st.isDirectory()) unlock(full);
            else chmodSync(full, 0o600);
          } catch {}
        }
      };
      unlock(sealRoot);
    } catch {}
    rmSync(sealRoot, { recursive: true, force: true });
  }
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
      governedNpmDir: path.resolve(args["governed-npm"]),
      releaseRef: process.env.RAVEN_RELEASE_REF,
      releaseSha: process.env.RAVEN_RELEASE_SHA,
      releaseTree: process.env.RAVEN_RELEASE_TREE,
      githubRef: process.env.GITHUB_REF,
      githubSha: process.env.GITHUB_SHA,
      remote: process.env.RAVEN_RELEASE_REMOTE ?? "origin",
    });
    console.log(`published exact verified tarball via governed npm ${result.governedNpm.version} (tree ${result.governedNpm.treeSha256.slice(0, 16)}…) under ${result.governedNode.version}; sealed sha256 ${result.sealedSha256}`);
  } catch (error) {
    console.error(`REFUSED publication: ${error.message}`);
    process.exit(1);
  }
}
