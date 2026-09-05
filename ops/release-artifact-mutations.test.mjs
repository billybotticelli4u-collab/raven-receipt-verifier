import assert from "node:assert/strict";
import {
  appendFileSync,
  copyFileSync,
  cpSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  renameSync,
  rmSync,
  symlinkSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

import { guardAndPublish } from "./publish-exact-release.mjs";
import {
  comparePackMetadataToActual,
  measureReleaseArtifact,
} from "./release-artifact-utils.mjs";
import {
  CANONICAL_TARBALL,
  EXPECTED_EXPORT_MAP,
  EXPECTED_PACKAGE_FILES,
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
import { verifyReleaseArtifact } from "./verify-release-artifact.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const SOURCE_PACKAGE = path.join(ROOT, "packages/verify-js");

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return result.stdout.trim();
};

const git = (cwd, ...args) => run("git", args, { cwd });

const packRecord = (actual) => ({
  name: PACKAGE_NAME,
  version: PACKAGE_VERSION,
  filename: actual.filename,
  size: actual.compressedBytes,
  unpackedSize: actual.unpackedBytes,
  shasum: actual.sha1,
  integrity: actual.integrity,
  entryCount: actual.fileCount,
  files: actual.files.map(({ path: filePath, size }) => ({ path: filePath, size })),
});

const writeJson = (target, value) => writeFileSync(target, `${JSON.stringify(value, null, 2)}\n`);

const createTar = (fixture, members = EXPECTED_PACKAGE_FILES) => {
  rmSync(path.join(fixture.artifactDir, CANONICAL_TARBALL), { force: true });
  run("tar", [
    "--format=ustar",
    "-czf",
    path.join(fixture.artifactDir, CANONICAL_TARBALL),
    "-C",
    fixture.packageParent,
    ...members.map((member) => `package/${member}`),
  ], { env: { ...process.env, COPYFILE_DISABLE: "1" } });
};

const refreshPack = (fixture) => {
  writeJson(fixture.packJsonPath, [{ filename: CANONICAL_TARBALL }]);
  const measured = measureReleaseArtifact(fixture);
  writeJson(fixture.packJsonPath, [packRecord(measured.actual)]);
  const final = measureReleaseArtifact(fixture);
  comparePackMetadataToActual(final);
  return final.actual;
};

const refreshMutableHandoff = (fixture) => {
  const actual = refreshPack(fixture);
  writeJson(fixture.handoffPath, {
    schema: "raven-receipt-verifier-artifact-handoff/2",
    artifact: actual,
    source: { commit: fixture.commit, tree: fixture.tree, ref: PUBLICATION_REF },
    toolchain: { node: "v22.18.0", npm: PINNED_NPM_VERSION },
  });
  return actual;
};

const initFixture = () => {
  const root = mkdtempSync(path.join(tmpdir(), "raven-artifact-mutations-"));
  const packageParent = path.join(root, "package-source");
  const packageRoot = path.join(packageParent, "package");
  const artifactDir = path.join(root, "artifact");
  const repo = path.join(root, "repo");
  const remote = path.join(root, "origin.git");
  mkdirSync(packageRoot, { recursive: true });
  mkdirSync(artifactDir);
  for (const relative of EXPECTED_PACKAGE_FILES) {
    const destination = path.join(packageRoot, relative);
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(path.join(SOURCE_PACKAGE, relative), destination);
  }
  run("git", ["init", repo]);
  git(repo, "config", "user.email", "release-test@invalid.example");
  git(repo, "config", "user.name", "Raven Release Test");
  writeFileSync(path.join(repo, "source.txt"), "exact source\n");
  mkdirSync(path.join(repo, ".github/workflows"), { recursive: true });
  copyFileSync(path.join(ROOT, ".github/workflows/verify-js-publish.yml"), path.join(repo, ".github/workflows/verify-js-publish.yml"));
  git(repo, "add", "source.txt", ".github");
  git(repo, "commit", "-m", "exact source");
  const commit = git(repo, "rev-parse", "HEAD");
  const tree = git(repo, "rev-parse", "HEAD^{tree}");
  run("git", ["init", "--bare", remote]);
  git(repo, "remote", "add", "origin", remote);
  git(repo, "push", "origin", `HEAD:${PUBLICATION_REF}`);

  const fixture = {
    root,
    packageParent,
    packageRoot,
    artifactDir,
    tarballDir: artifactDir,
    packJsonPath: path.join(artifactDir, "pack.json"),
    handoffPath: path.join(root, "handoff.json"),
    frozenPath: path.join(root, "frozen.json"),
    repo,
    commit,
    tree,
  };
  createTar(fixture);
  const actual = refreshMutableHandoff(fixture);
  writeJson(fixture.frozenPath, {
    schema: "raven-receipt-verifier-release-identity/2",
    package: {
      name: PACKAGE_NAME,
      version: PACKAGE_VERSION,
      nodeFloor: NODE_FLOOR,
      runtimeDependencies: 0,
      exportMap: EXPECTED_EXPORT_MAP,
    },
    toolchain: { npm: PINNED_NPM_VERSION, nodeExecutions: ["v22.18.0", "v24.20.0"] },
    upstreamSource: {
      commit: UPSTREAM_ACCEPTED_COMMIT,
      tree: UPSTREAM_ACCEPTED_TREE,
      packageTree: UPSTREAM_ACCEPTED_PACKAGE_TREE,
    },
    publicMirror: {
      repository: PUBLIC_REPOSITORY.replace(/^git\+/, "").replace(/\.git$/, ""),
      packageDirectory: "packages/verify-js",
      publicationRef: PUBLICATION_REF,
      commitBinding: "RAVEN_RELEASE_SHA == GITHUB_SHA == HEAD == freshly-resolved publicationRef^{commit}",
      treeBinding: "RAVEN_RELEASE_TREE == HEAD^{tree} == freshly-resolved publicationRef^{commit}^{tree}",
      packageTree: PUBLIC_MIRROR_PACKAGE_TREE,
    },
    artifact: actual,
  });
  return fixture;
};

const verifyArgs = (fixture) => ({
  packJsonPath: fixture.packJsonPath,
  tarballDir: fixture.artifactDir,
  artifactIdentityPath: fixture.handoffPath,
  frozenIdentityPath: fixture.frozenPath,
  confirmVersion: PACKAGE_VERSION,
  releaseRef: PUBLICATION_REF,
  releaseSha: fixture.commit,
  releaseTree: fixture.tree,
  cwd: fixture.repo,
});

const withFixture = (body) => {
  const fixture = initFixture();
  try {
    return body(fixture);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
};

test("positive control: actual tar bytes, npm metadata, frozen identity, and handoff agree", () => withFixture((fixture) => {
  const result = verifyReleaseArtifact(verifyArgs(fixture));
  assert.equal(result.actual.fileCount, 48);
  assert.equal(result.actual.files.some((file) => file.path === "LICENSE"), true);
}));

test("M9 modified tar member with stale identity turns RED", () => withFixture((fixture) => {
  appendFileSync(path.join(fixture.packageRoot, "README.md"), "\nmutation M9\n");
  createTar(fixture);
  assert.throws(() => verifyReleaseArtifact(verifyArgs(fixture)));
}));

test("M10 regenerated mutable pack/handoff cannot authorize modified tar bytes", () => withFixture((fixture) => {
  appendFileSync(path.join(fixture.packageRoot, "README.md"), "\nmutation M10\n");
  createTar(fixture);
  refreshMutableHandoff(fixture);
  assert.throws(() => verifyReleaseArtifact(verifyArgs(fixture)), /frozen artifact/);
}));

test("M11 missing LICENSE and a missing verifier output each turn RED", () => withFixture((fixture) => {
  unlinkSync(path.join(fixture.packageRoot, "LICENSE"));
  createTar(fixture, EXPECTED_PACKAGE_FILES.filter((entry) => entry !== "LICENSE"));
  assert.throws(() => measureReleaseArtifact(fixture), /inventory/);
  copyFileSync(path.join(SOURCE_PACKAGE, "LICENSE"), path.join(fixture.packageRoot, "LICENSE"));
  unlinkSync(path.join(fixture.packageRoot, "dist/verifyReceiptV1.js"));
  createTar(fixture, EXPECTED_PACKAGE_FILES.filter((entry) => entry !== "dist/verifyReceiptV1.js"));
  assert.throws(() => measureReleaseArtifact(fixture), /inventory/);
}));

test("M12 unexpected proposed output turns RED", () => withFixture((fixture) => {
  writeFileSync(path.join(fixture.packageRoot, "dist/proposed.js"), "export {};\n");
  createTar(fixture, [...EXPECTED_PACKAGE_FILES, "dist/proposed.js"]);
  assert.throws(() => measureReleaseArtifact(fixture), /inventory/);
}));

test("M13 runtime dependency added inside actual tar turns RED", () => withFixture((fixture) => {
  const manifestPath = path.join(fixture.packageRoot, "package.json");
  const manifest = JSON.parse(readFileSync(manifestPath));
  manifest.dependencies = { attacker: "1.0.0" };
  writeJson(manifestPath, manifest);
  createTar(fixture);
  assert.throws(() => measureReleaseArtifact(fixture), /runtime dependencies/);
}));

test("M14 proposed/withheld export added inside actual tar turns RED", () => withFixture((fixture) => {
  const manifestPath = path.join(fixture.packageRoot, "package.json");
  const manifest = JSON.parse(readFileSync(manifestPath));
  manifest.exports["./proposed"] = "./dist/proposed.js";
  writeJson(manifestPath, manifest);
  createTar(fixture);
  assert.throws(() => measureReleaseArtifact(fixture), /export map/);
}));

test("M15 substituted public repository metadata inside actual tar turns RED", () => withFixture((fixture) => {
  const manifestPath = path.join(fixture.packageRoot, "package.json");
  const manifest = JSON.parse(readFileSync(manifestPath));
  manifest.repository.url = "git+https://example.invalid/substitute.git";
  writeJson(manifestPath, manifest);
  createTar(fixture);
  assert.throws(() => measureReleaseArtifact(fixture), /installed repository/);
}));

test("M16 a second tgz in the handoff directory turns RED", () => withFixture((fixture) => {
  copyFileSync(path.join(fixture.artifactDir, CANONICAL_TARBALL), path.join(fixture.artifactDir, "second.tgz"));
  assert.throws(() => measureReleaseArtifact(fixture), /exactly/);
}));

test("M17 renamed canonical tarball turns RED", () => withFixture((fixture) => {
  renameSync(path.join(fixture.artifactDir, CANONICAL_TARBALL), path.join(fixture.artifactDir, "renamed.tgz"));
  assert.throws(() => measureReleaseArtifact(fixture), /exactly/);
}));

test("symlink escape and path-traversal member turn RED", () => withFixture((fixture) => {
  const outside = path.join(fixture.root, "outside.tgz");
  copyFileSync(path.join(fixture.artifactDir, CANONICAL_TARBALL), outside);
  unlinkSync(path.join(fixture.artifactDir, CANONICAL_TARBALL));
  symlinkSync(outside, path.join(fixture.artifactDir, CANONICAL_TARBALL));
  assert.throws(() => measureReleaseArtifact(fixture), /regular file/);

  unlinkSync(path.join(fixture.artifactDir, CANONICAL_TARBALL));
  createTar(fixture);
  const tarball = path.join(fixture.artifactDir, CANONICAL_TARBALL);
  const decoded = gunzipSync(readFileSync(tarball));
  decoded.fill(0, 0, 100);
  decoded.write("package/../evil", 0, "utf8");
  decoded.fill(0x20, 148, 156);
  let checksum = 0;
  for (let index = 0; index < 512; index += 1) checksum += decoded[index];
  decoded.write(`${checksum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
  writeFileSync(tarball, gzipSync(decoded));
  assert.throws(() => measureReleaseArtifact(fixture), /tar|unsafe|exited/i);
}));

test("M18 replacement after prior verification is caught by final wrapper before publish", () => withFixture((fixture) => {
  verifyReleaseArtifact(verifyArgs(fixture));
  let publishCalls = 0;
  guardAndPublish({
    ...verifyArgs(fixture),
    githubRef: PUBLICATION_REF,
    githubSha: fixture.commit,
    remote: "origin",
    publisher: (tarball) => {
      publishCalls += 1;
      // The wrapper seals the authenticated bytes into a private copy; npm
      // never receives the shared artifact path.
      assert.notEqual(tarball, path.join(fixture.artifactDir, CANONICAL_TARBALL));
      assert.equal(path.basename(tarball), CANONICAL_TARBALL);
      assert.equal(createHash("sha256").update(readFileSync(tarball)).digest("hex"), JSON.parse(readFileSync(fixture.frozenPath)).artifact.sha256);
    },
  });
  assert.equal(publishCalls, 1, "positive control must reach the injected non-publishing sink");

  appendFileSync(path.join(fixture.packageRoot, "README.md"), "\nreplacement after earlier verification\n");
  createTar(fixture);
  refreshMutableHandoff(fixture);
  assert.throws(() => guardAndPublish({
    ...verifyArgs(fixture),
    githubRef: PUBLICATION_REF,
    githubSha: fixture.commit,
    remote: "origin",
    publisher: () => { publishCalls += 1; },
  }), /frozen artifact/);
  assert.equal(publishCalls, 1, "altered bytes must not reach the publish sink");
}));

test("handoff source.ref mutation cannot overrule actual protected ref", () => withFixture((fixture) => {
  const handoff = JSON.parse(readFileSync(fixture.handoffPath));
  handoff.source.ref = "refs/heads/attacker";
  writeJson(fixture.handoffPath, handoff);
  assert.throws(() => verifyReleaseArtifact(verifyArgs(fixture)), /handoff ref/);
}));
