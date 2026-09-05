// Hardening mutations closing the structural gaps named by the independent
// review of 5afdaf7d (C2, S1, E9, S11/S11b, S13, S15, permission broadening).
// Each mutation must turn RED. Positive controls prove the instruments are live.
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

import { scanInvokedPublicationHelpers, validateWorkflowText } from "./publication-policy.mjs";
import { guardAndPublish } from "./publish-exact-release.mjs";
import { measureReleaseArtifact } from "./release-artifact-utils.mjs";
import {
  APPROVED_ACTIONS,
  CANONICAL_TARBALL,
  EXPECTED_EXPORT_MAP,
  EXPECTED_PACKAGE_FILES,
  NODE_FLOOR,
  PACKAGE_NAME,
  PACKAGE_VERSION,
  PINNED_NPM_VERSION,
  PUBLICATION_REF,
  PUBLICATION_REGISTRY,
  PUBLIC_MIRROR_PACKAGE_TREE,
  PUBLIC_REPOSITORY,
  UPSTREAM_ACCEPTED_COMMIT,
  UPSTREAM_ACCEPTED_PACKAGE_TREE,
  UPSTREAM_ACCEPTED_TREE,
} from "./release-policy.mjs";
import { gitObjectHash, gitTreeHash, verifyCorrespondence } from "./verify-byte-correspondence.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const WORKFLOW = readFileSync(path.join(ROOT, ".github/workflows/verify-js-publish.yml"), "utf8");
const MANIFEST = JSON.parse(readFileSync(path.join(ROOT, "release/private-public-byte-correspondence.json"), "utf8"));
const SOURCE_PACKAGE = path.join(ROOT, "packages/verify-js");

const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return result.stdout.trim();
};
const git = (cwd, ...args) => run("git", ["-c", "tag.gpgSign=false", "-c", "commit.gpgSign=false", ...args], { cwd });
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const red = (label, mutated) => {
  const failures = validateWorkflowText(mutated);
  assert.ok(failures.length > 0, `${label} survived workflow policy`);
  return failures;
};
const inJob = (job, from, to) => {
  const start = WORKFLOW.indexOf(`\n  ${job}:`);
  const at = WORKFLOW.indexOf(from, start);
  assert.ok(start >= 0 && at >= 0, `anchor missing for ${job}: ${from}`);
  return WORKFLOW.slice(0, at) + to + WORKFLOW.slice(at + from.length);
};

test("positive control: current workflow satisfies the hardened structural policy", () => {
  assert.deepEqual(validateWorkflowText(WORKFLOW), []);
  assert.deepEqual(scanInvokedPublicationHelpers({ root: ROOT, workflow: WORKFLOW }), []);
});

// ---------------------------------------------------------------- 1. oracle
const mirrorFixture = () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-hardening-corr-"));
  for (const entry of MANIFEST.entries) {
    const destination = path.join(scratch, entry.publicPath);
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(path.join(ROOT, entry.publicPath), destination);
  }
  git(scratch, "init", "-q");
  git(scratch, "add", "packages/verify-js");
  return scratch;
};
const regenerateManifest = (root, manifest) => {
  // Exactly what an attacker with public write access would do: make the
  // manifest self-consistent with the bytes now on disk.
  const forged = structuredClone(manifest);
  for (const entry of forged.entries) {
    const publicBlob = gitObjectHash("blob", readFileSync(path.join(root, entry.publicPath)));
    entry.publicBlob = publicBlob;
    if (entry.relationship === "IDENTICAL") entry.privateBlob = publicBlob;
  }
  const strip = (p) => p.replace(/^packages\/verify-js\//, "");
  forged.upstreamSource.packageTree = gitTreeHash(forged.entries.map((e) => ({ path: strip(e.privatePath), mode: e.mode, hash: e.privateBlob })));
  forged.publicMirror.packageTree = gitTreeHash(forged.entries.map((e) => ({ path: strip(e.publicPath), mode: e.mode, hash: e.publicBlob })));
  return forged;
};

test("positive control: committed manifest reconstructs the policy-pinned trees from actual bytes", () => {
  const result = verifyCorrespondence({ root: ROOT, manifest: MANIFEST });
  assert.equal(result.privateTree, UPSTREAM_ACCEPTED_PACKAGE_TREE);
  assert.equal(result.publicTree, PUBLIC_MIRROR_PACKAGE_TREE);
  assert.equal(MANIFEST.upstreamSource.commit, UPSTREAM_ACCEPTED_COMMIT);
  assert.equal(MANIFEST.upstreamSource.tree, UPSTREAM_ACCEPTED_TREE);
});

test("M26 (C2) modified verifier source + self-consistently regenerated manifest turns RED", () => {
  const scratch = mirrorFixture();
  try {
    const target = path.join(scratch, "packages/verify-js/src/verifyReceiptV1.ts");
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// attacker: trust flip lives here\n`);
    git(scratch, "add", "packages/verify-js");
    const forged = regenerateManifest(scratch, MANIFEST);
    assert.notEqual(forged.upstreamSource.packageTree, UPSTREAM_ACCEPTED_PACKAGE_TREE, "fixture must actually change the package tree");
    assert.throws(() => verifyCorrespondence({ root: scratch, manifest: forged }), /accepted package tree|policy/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("M26b forged manifest that keeps the policy tree strings but lies about blobs turns RED", () => {
  const scratch = mirrorFixture();
  try {
    const target = path.join(scratch, "packages/verify-js/src/verifyReceiptV1.ts");
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// attacker\n`);
    git(scratch, "add", "packages/verify-js");
    const forged = regenerateManifest(scratch, MANIFEST);
    forged.upstreamSource.packageTree = UPSTREAM_ACCEPTED_PACKAGE_TREE;
    forged.publicMirror.packageTree = PUBLIC_MIRROR_PACKAGE_TREE;
    assert.throws(() => verifyCorrespondence({ root: scratch, manifest: forged }), /accepted package tree|public package tree|policy/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("M26c unauthorized package.json delta beyond repository metadata turns RED", () => {
  const scratch = mirrorFixture();
  try {
    const target = path.join(scratch, "packages/verify-js/package.json");
    const manifest = JSON.parse(readFileSync(target, "utf8"));
    manifest.scripts.postinstall = "node -e 0";
    writeFileSync(target, `${JSON.stringify(manifest, null, 2)}\n`);
    git(scratch, "add", "packages/verify-js");
    const forged = regenerateManifest(scratch, MANIFEST);
    assert.throws(() => verifyCorrespondence({ root: scratch, manifest: forged }));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- 2. atomicity
const artifactFixture = () => {
  const root = mkdtempSync(path.join(tmpdir(), "raven-hardening-seal-"));
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
  run("tar", ["--format=ustar", "-czf", path.join(artifactDir, CANONICAL_TARBALL), "-C", packageParent, ...EXPECTED_PACKAGE_FILES.map((m) => `package/${m}`)], { env: { ...process.env, COPYFILE_DISABLE: "1" } });
  const packJsonPath = path.join(artifactDir, "pack.json");
  writeFileSync(packJsonPath, JSON.stringify([{ filename: CANONICAL_TARBALL }]));
  const first = measureReleaseArtifact({ packJsonPath, tarballDir: artifactDir }).actual;
  writeFileSync(packJsonPath, JSON.stringify([{ name: PACKAGE_NAME, version: PACKAGE_VERSION, filename: CANONICAL_TARBALL, size: first.compressedBytes, unpackedSize: first.unpackedBytes, shasum: first.sha1, integrity: first.integrity, entryCount: first.fileCount, files: first.files.map(({ path: p, size }) => ({ path: p, size })) }]));
  const actual = measureReleaseArtifact({ packJsonPath, tarballDir: artifactDir }).actual;
  run("git", ["init", "-q", repo]);
  git(repo, "config", "user.email", "release-test@invalid.example");
  git(repo, "config", "user.name", "Raven Release Test");
  writeFileSync(path.join(repo, "source.txt"), "exact source\n");
  mkdirSync(path.join(repo, ".github/workflows"), { recursive: true });
  copyFileSync(path.join(ROOT, ".github/workflows/verify-js-publish.yml"), path.join(repo, ".github/workflows/verify-js-publish.yml"));
  git(repo, "add", "source.txt", ".github");
  git(repo, "commit", "-q", "-m", "exact source");
  const commit = git(repo, "rev-parse", "HEAD");
  const tree = git(repo, "rev-parse", "HEAD^{tree}");
  run("git", ["init", "-q", "--bare", remote]);
  git(repo, "remote", "add", "origin", remote);
  git(repo, "push", "-q", "origin", `HEAD:${PUBLICATION_REF}`);
  const handoffPath = path.join(root, "handoff.json");
  const frozenPath = path.join(root, "frozen.json");
  writeFileSync(handoffPath, JSON.stringify({ schema: "raven-receipt-verifier-artifact-handoff/2", artifact: actual, source: { commit, tree, ref: PUBLICATION_REF }, toolchain: { node: "v22.18.0", npm: PINNED_NPM_VERSION } }));
  writeFileSync(frozenPath, JSON.stringify({
    schema: "raven-receipt-verifier-release-identity/2",
    package: { name: PACKAGE_NAME, version: PACKAGE_VERSION, nodeFloor: NODE_FLOOR, runtimeDependencies: 0, exportMap: EXPECTED_EXPORT_MAP },
    toolchain: { npm: PINNED_NPM_VERSION, nodeExecutions: ["v22.18.0", "v24.20.0"] },
    upstreamSource: { commit: UPSTREAM_ACCEPTED_COMMIT, tree: UPSTREAM_ACCEPTED_TREE, packageTree: UPSTREAM_ACCEPTED_PACKAGE_TREE },
    publicMirror: { repository: PUBLIC_REPOSITORY.replace(/^git\+/, "").replace(/\.git$/, ""), packageDirectory: "packages/verify-js", publicationRef: PUBLICATION_REF, commitBinding: "RAVEN_RELEASE_SHA == GITHUB_SHA == HEAD == freshly-resolved publicationRef^{commit}", treeBinding: "RAVEN_RELEASE_TREE == HEAD^{tree} == freshly-resolved publicationRef^{commit}^{tree}", packageTree: PUBLIC_MIRROR_PACKAGE_TREE },
    artifact: actual,
  }));
  const args = { packJsonPath, tarballDir: artifactDir, artifactIdentityPath: handoffPath, frozenIdentityPath: frozenPath, confirmVersion: PACKAGE_VERSION, releaseRef: PUBLICATION_REF, releaseSha: commit, releaseTree: tree, githubRef: PUBLICATION_REF, githubSha: commit, remote: "origin", cwd: repo };
  return { root, artifactDir, tarball: path.join(artifactDir, CANONICAL_TARBALL), actual, args };
};
const withArtifact = (body) => { const f = artifactFixture(); try { return body(f); } finally { rmSync(f.root, { recursive: true, force: true }); } };
const swappedBytes = (tarball) => gzipSync(Buffer.concat([gunzipSync(readFileSync(tarball)), Buffer.alloc(512)]));

test("positive control: publisher receives a sealed private copy whose bytes equal the verified identity", () => withArtifact((f) => {
  let seen = null;
  const result = guardAndPublish({ ...f.args, publisher: (tarball) => { seen = { tarball, sha256: sha256(readFileSync(tarball)) }; } });
  assert.ok(seen, "publisher must be reached");
  assert.notEqual(seen.tarball, f.tarball, "publisher must not receive the shared artifact path");
  assert.equal(path.basename(seen.tarball), CANONICAL_TARBALL);
  assert.equal(seen.sha256, f.actual.sha256);
  assert.equal(result.sealedSha256, f.actual.sha256);
}));

test("M27 (E9) concurrent replacement of the shared tarball during verify→publish cannot reach npm", () => withArtifact((f) => {
  const evil = swappedBytes(f.tarball);
  const evilPath = path.join(f.root, "evil.bin");
  writeFileSync(evilPath, evil);
  // A hostile sibling process hammers the shared artifact path for the whole window.
  const swapper = spawn(process.execPath, ["-e", `
    const fs = require("node:fs"); const evil = fs.readFileSync(${JSON.stringify(evilPath)});
    const end = Date.now() + 4000; while (Date.now() < end) { try { fs.writeFileSync(${JSON.stringify(f.tarball)}, evil); } catch {} }
  `], { stdio: "ignore" });
  try {
    let published = null;
    let outcome;
    try {
      guardAndPublish({ ...f.args, publisher: (tarball) => {
        const until = Date.now() + 300; while (Date.now() < until) { /* hold the boundary open */ }
        published = sha256(readFileSync(tarball));
      } });
      outcome = "published";
    } catch (error) {
      outcome = `refused: ${error.message.split("\n")[0]}`;
    }
    // Either the wrapper refused before publishing (shared path already swapped
    // at measurement time) or it published the sealed bytes. Never the evil bytes.
    if (outcome === "published") assert.equal(published, f.actual.sha256, "sealed copy must carry verified bytes");
    else assert.match(outcome, /refused/);
    assert.notEqual(published, sha256(evil), "evil bytes must never reach the publisher");
  } finally {
    swapper.kill();
  }
}));

test("M27b sealed copy tampered at the publication boundary is refused before npm runs", () => withArtifact((f) => {
  let calls = 0;
  assert.throws(() => guardAndPublish({ ...f.args,
    beforePublish: (sealed) => writeFileSync(sealed, swappedBytes(f.tarball)),
    publisher: () => { calls += 1; } }), /sealed/);
  assert.equal(calls, 0);
}));

test("M27c sealed copy altered while npm runs is reported as an uncertain publication", () => withArtifact((f) => {
  assert.throws(() => guardAndPublish({ ...f.args, publisher: (sealed) => writeFileSync(sealed, swappedBytes(f.tarball)) }), /sealed|uncertain/i);
}));

test("M28 (S15 runtime) publish refuses when npm resolves a registry other than the pinned endpoint", () => withArtifact((f) => {
  const previous = process.env.npm_config_registry;
  process.env.npm_config_registry = "https://registry.example.invalid/";
  let calls = 0;
  try {
    assert.throws(() => guardAndPublish({ ...f.args, publisher: () => { calls += 1; } }), /registry/);
    assert.equal(calls, 0);
  } finally {
    if (previous === undefined) delete process.env.npm_config_registry; else process.env.npm_config_registry = previous;
  }
}));

// ---------------------------------------------------------------- 3. publish job allowlist
test("M29 (S1) inserted SHA-pinned uses: step in the publish job turns RED", () => {
  red("S1", inJob("publish", "          path: ${{ runner.temp }}/release-package\n", "          path: ${{ runner.temp }}/release-package\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          path: attacker\n"));
  red("S1 unknown action", inJob("publish", "          path: ${{ runner.temp }}/release-package\n", "          path: ${{ runner.temp }}/release-package\n      - uses: attacker/swap-tarball@0123456789abcdef0123456789abcdef01234567\n"));
});

test("M29b step removal, reordering, or edited run text in the publish job turns RED", () => {
  red("removed npm gate", inJob("publish", "      - name: Assert pinned npm CLI\n        run: node ops/npm-version-gate.mjs \"${RAVEN_PINNED_NPM_VERSION}\"\n", ""));
  red("edited publish args", inJob("publish", "--frozen-identity release/release-identity.json", "--frozen-identity release/alt-identity.json"));
  red("edited tarball dir", inJob("publish", '--tarball-dir "$RUNNER_TEMP/release-package"', '--tarball-dir "$RUNNER_TEMP/alt"'));
  red("extra checkout with persisted credentials", inJob("publish", "          persist-credentials: false\n", "          persist-credentials: false\n      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n        with:\n          persist-credentials: true\n"));
});

test("M29d with: blocks are part of a step's identity: checkout ref / download path retargets turn RED", () => {
  red("S23 checkout ref main", inJob("publish", "          ref: ${{ inputs.release_sha }}\n", "          ref: main\n"));
  red("download path retarget", inJob("publish", "          path: ${{ runner.temp }}/release-package\n", "          path: ${{ runner.temp }}/attacker\n"));
  red("upload evidence path", inJob("publish", "            release/release-identity.json\n", "            release/release-identity.json\n            ~/.npmrc\n"));
  red("fetch-depth removed", inJob("publish", "          fetch-depth: 0\n", ""));
});

test("M29e env:/if: injection on an allowlisted step turns RED", () => {
  red("NODE_OPTIONS on publish", inJob("publish", "      - name: Final in-process verification and immediate exact-tarball publish\n        env:\n", "      - name: Final in-process verification and immediate exact-tarball publish\n        env:\n          NODE_OPTIONS: --require /tmp/evil.js\n"));
  red("if: false on ref gate", inJob("publish", "      - name: Resolve authorized ref to exact SHA and tree\n", "      - name: Resolve authorized ref to exact SHA and tree\n        if: false\n"));
  red("continue-on-error on ref gate", inJob("publish", "      - name: Resolve authorized ref to exact SHA and tree\n", "      - name: Resolve authorized ref to exact SHA and tree\n        continue-on-error: true\n"));
  red("shell: changed", inJob("package-artifact", "      - name: Pack exactly once\n", "      - name: Pack exactly once\n        shell: bash -e {0}\n"));
  red("working-directory changed", inJob("publish", "      - name: Final in-process verification and immediate exact-tarball publish\n", "      - name: Final in-process verification and immediate exact-tarball publish\n        working-directory: attacker\n"));
});

test("M29c gate jobs are allowlisted too: inserted helper outside ops/ turns RED", () => {
  red("S16", WORKFLOW.replace("node ops/verify-byte-correspondence.mjs", "node tools/verify-byte-correspondence.mjs"));
  red("S8 indirect pack", inJob("package-artifact", "          npm pack --json", "          node \"$(npm root -g)/npm/bin/npm-cli.js\" pack --pack-destination \"$RUNNER_TEMP/alt\"\n          npm pack --json"));
  red("S9 npx pack", inJob("package-artifact", "          npm pack --json", "          npx npm pack --pack-destination \"$RUNNER_TEMP/alt\"\n          npm pack --json"));
});

// ---------------------------------------------------------------- 4. action SHA policy
test("M30 (S11/S11b) any external action not at its approved commit SHA turns RED", () => {
  for (const [action, sha] of Object.entries(APPROVED_ACTIONS)) {
    assert.match(sha, /^[0-9a-f]{40}$/);
    assert.ok(WORKFLOW.includes(`${action}@${sha}`), `${action} must be used at its approved SHA`);
    const failures = red(`${action} SHA substitution`, WORKFLOW.replaceAll(`${action}@${sha}`, `${action}@ffffffffffffffffffffffffffffffffffffffff`));
    assert.ok(failures.some((f) => f.includes(action)), `failure must name ${action}`);
  }
  red("forked checkout", WORKFLOW.replaceAll("actions/checkout@", "attacker/checkout@"));
  red("unknown action appended", inJob("source-gate", "      - name: Package contract tests", "      - uses: actions/cache@0123456789abcdef0123456789abcdef01234567\n      - name: Package contract tests"));
});

// ---------------------------------------------------------------- 5. /pubkey negative control
test("M31 (S13) dynamic /pubkey trust bootstrap in the release ceremony turns RED", () => {
  red("curl pubkey", inJob("source-gate", "      - name: Package contract tests", "      - name: Fetch trust\n        run: curl -s https://raven-hosted-verifier.onrender.com/pubkey > trusted.json\n      - name: Package contract tests"));
  red("pubkey env", WORKFLOW.replace('  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n', '  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n  RAVEN_TRUSTED_KEYS_URL: "https://raven-hosted-verifier.onrender.com/pubkey"\n'));
  red("trusted keys env", WORKFLOW.replace('  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n', '  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n  RAVEN_TRUSTED_KEYS: "MCowBQYDK2VwAyEA"\n'));
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-hardening-pubkey-"));
  try {
    mkdirSync(path.join(scratch, "ops"));
    writeFileSync(path.join(scratch, "ops/trust.mjs"), 'const keys = await fetch("https://raven-hosted-verifier.onrender.com/pubkey").then((r) => r.json());\nconsole.log(keys);\n');
    const failures = scanInvokedPublicationHelpers({ root: scratch, workflow: "run: node ops/trust.mjs\n" });
    assert.ok(failures.some((f) => f.includes("trust.mjs")), "helper fetching /pubkey must be named");
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------- 6. registry endpoint
test("M32 (S15) registry endpoint is pinned; any alternate or extra registry target turns RED", () => {
  assert.equal(PUBLICATION_REGISTRY, "https://registry.npmjs.org");
  assert.ok(WORKFLOW.includes(`registry-url: "${PUBLICATION_REGISTRY}"`));
  red("rogue registry-url", WORKFLOW.replace(`registry-url: "${PUBLICATION_REGISTRY}"`, 'registry-url: "https://registry.example.invalid"'));
  red("registry-url removed", WORKFLOW.replace(`          registry-url: "${PUBLICATION_REGISTRY}"\n`, ""));
  red("second registry-url on a gate", inJob("source-gate", "          node-version: ${{ matrix.node-version }}\n", `          node-version: \${{ matrix.node-version }}\n          registry-url: "${PUBLICATION_REGISTRY}"\n`));
  red("NPM_CONFIG_REGISTRY env", WORKFLOW.replace('  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n', '  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n  NPM_CONFIG_REGISTRY: "https://registry.example.invalid"\n'));
  red("--registry flag", inJob("publish", "            --confirm-version \"${{ inputs.confirm_version }}\"", "            --confirm-version \"${{ inputs.confirm_version }}\" --registry https://registry.example.invalid"));
  red(".npmrc write", inJob("publish", "      - name: Final in-process", "      - name: Prep\n        run: echo registry=https://registry.example.invalid > ~/.npmrc\n      - name: Final in-process"));
});

// ---------------------------------------------------------------- 7. permission structure
test("M33 permission broadening on any job turns RED", () => {
  const jobs = ["source-gate", "package-artifact", "tarball-gate"];
  for (const job of jobs) {
    red(`${job} contents: write`, inJob(job, "    permissions:\n      contents: read\n", "    permissions:\n      contents: write\n"));
    red(`${job} write-all`, inJob(job, "    permissions:\n      contents: read\n", "    permissions: write-all\n"));
    red(`${job} id-token`, inJob(job, "    permissions:\n      contents: read\n", "    permissions:\n      contents: read\n      id-token: write\n"));
    red(`${job} packages`, inJob(job, "    permissions:\n      contents: read\n", "    permissions:\n      contents: read\n      packages: write\n"));
  }
  for (const extra of ["actions: write", "packages: write", "pull-requests: write", "contents: write", "deployments: write"]) {
    red(`publish + ${extra}`, inJob("publish", "      id-token: write\n", `      id-token: write\n      ${extra}\n`));
  }
  red("publish contents: write", inJob("publish", "      contents: read\n      id-token: write\n", "      contents: write\n      id-token: write\n"));
  red("global write-all", WORKFLOW.replace("permissions:\n  contents: read\n", "permissions: write-all\n"));
  red("global id-token", WORKFLOW.replace("permissions:\n  contents: read\n", "permissions:\n  contents: read\n  id-token: write\n"));
  red("environment removed", WORKFLOW.replace("    environment: npm-release\n", ""));
  red("environment renamed", WORKFLOW.replace("    environment: npm-release\n", "    environment: npm-release-2\n"));
});

test("M34 node matrix and pinned-npm env stay governed", () => {
  red("node 20 matrix", WORKFLOW.replaceAll('node-version: ["22.18.0", "24"]', 'node-version: ["20"]'));
  red("npm env drift", WORKFLOW.replace('RAVEN_PINNED_NPM_VERSION: "11.18.0"', 'RAVEN_PINNED_NPM_VERSION: "11.17.0"'));
  red("publish node drift", inJob("publish", '          node-version: "22.18.0"\n', '          node-version: "20"\n'));
});
