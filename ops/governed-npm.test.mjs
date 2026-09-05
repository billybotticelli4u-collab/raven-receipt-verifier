// Publisher-identity boundary (v5). The invariant under test: no process
// capable of executing `npm publish` may observe or submit bytes other than
// the frozen artifact, and the publisher executable is the byte-pinned
// governed npm CLI run by absolute path under the governed Node — never a
// PATH-resolved, self-attesting program.
import assert from "node:assert/strict";
import { chmodSync, copyFileSync, cpSync, existsSync, linkSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { gunzipSync, gzipSync } from "node:zlib";

import { copyGovernedNpmTreeIntoSeal, measureNpmTree, sealGovernedNpmExecution, verifyGovernedNpm, verifyGovernedNpmTarball } from "./governed-npm.mjs";
import { assertNoForbiddenEnvironment, buildPublishEnvironment, guardAndPublish } from "./publish-exact-release.mjs";
import { measureReleaseArtifact } from "./release-artifact-utils.mjs";
import {
  CANONICAL_TARBALL, EXPECTED_EXPORT_MAP, EXPECTED_PACKAGE_FILES, GOVERNED_NPM, NODE_FLOOR, PACKAGE_NAME, PACKAGE_VERSION,
  PINNED_NPM_VERSION, PUBLICATION_REF, PUBLICATION_REGISTRY, PUBLIC_MIRROR_PACKAGE_TREE, PUBLIC_REPOSITORY, PUBLISH_ENV_PASSTHROUGH,
  UPSTREAM_ACCEPTED_COMMIT, UPSTREAM_ACCEPTED_PACKAGE_TREE, UPSTREAM_ACCEPTED_TREE, WORKFLOW_PATH,
} from "./release-policy.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const GOVERNED = process.env.RAVEN_GOVERNED_NPM_DIR ?? (process.env.RUNNER_TEMP ? path.join(process.env.RUNNER_TEMP, "governed-npm/package") : null);
// Fail, never skip: a missing governed npm would make every property below vacuous.
assert.ok(GOVERNED && existsSync(GOVERNED), "RAVEN_GOVERNED_NPM_DIR must point at a verified governed npm package directory");

const sha256 = (b) => createHash("sha256").update(b).digest("hex");
const run = (c, a, o = {}) => { const r = spawnSync(c, a, { encoding: "utf8", ...o }); if (r.status !== 0) throw new Error(r.stderr || r.stdout); return r.stdout.trim(); };
const git = (cwd, ...a) => run("git", ["-c", "tag.gpgSign=false", "-c", "commit.gpgSign=false", ...a], { cwd });

const fixture = () => {
  const root = mkdtempSync(path.join(tmpdir(), "raven-governed-npm-"));
  const packageParent = path.join(root, "package-source"), packageRoot = path.join(packageParent, "package"), artifactDir = path.join(root, "artifact"), repo = path.join(root, "repo"), remote = path.join(root, "origin.git");
  mkdirSync(packageRoot, { recursive: true }); mkdirSync(artifactDir);
  for (const rel of EXPECTED_PACKAGE_FILES) { const d = path.join(packageRoot, rel); mkdirSync(path.dirname(d), { recursive: true }); copyFileSync(path.join(ROOT, "packages/verify-js", rel), d); }
  run("tar", ["--format=ustar", "-czf", path.join(artifactDir, CANONICAL_TARBALL), "-C", packageParent, ...EXPECTED_PACKAGE_FILES.map((m) => `package/${m}`)], { env: { ...process.env, COPYFILE_DISABLE: "1" } });
  const packJsonPath = path.join(artifactDir, "pack.json");
  writeFileSync(packJsonPath, JSON.stringify([{ filename: CANONICAL_TARBALL }]));
  const a0 = measureReleaseArtifact({ packJsonPath, tarballDir: artifactDir }).actual;
  writeFileSync(packJsonPath, JSON.stringify([{ name: PACKAGE_NAME, version: PACKAGE_VERSION, filename: CANONICAL_TARBALL, size: a0.compressedBytes, unpackedSize: a0.unpackedBytes, shasum: a0.sha1, integrity: a0.integrity, entryCount: a0.fileCount, files: a0.files.map(({ path: p, size }) => ({ path: p, size })) }]));
  const actual = measureReleaseArtifact({ packJsonPath, tarballDir: artifactDir }).actual;
  run("git", ["init", "-q", repo]); git(repo, "config", "user.email", "t@x"); git(repo, "config", "user.name", "t");
  writeFileSync(path.join(repo, "s"), "s"); mkdirSync(path.join(repo, path.dirname(WORKFLOW_PATH)), { recursive: true }); copyFileSync(path.join(ROOT, WORKFLOW_PATH), path.join(repo, WORKFLOW_PATH));
  git(repo, "add", "-A"); git(repo, "commit", "-q", "-m", "s"); const commit = git(repo, "rev-parse", "HEAD"), tree = git(repo, "rev-parse", "HEAD^{tree}");
  run("git", ["init", "-q", "--bare", remote]); git(repo, "remote", "add", "origin", remote); git(repo, "push", "-q", "origin", `HEAD:${PUBLICATION_REF}`);
  const governed = verifyGovernedNpm(GOVERNED);
  const handoffPath = path.join(root, "handoff.json"), frozenPath = path.join(root, "frozen.json");
  writeFileSync(handoffPath, JSON.stringify({ schema: "raven-receipt-verifier-artifact-handoff/2", artifact: actual, source: { commit, tree, ref: PUBLICATION_REF }, toolchain: { node: "v22.18.0", npm: PINNED_NPM_VERSION, npmArtifact: { cliSha256: governed.cliSha256, treeSha256: governed.treeSha256, fileCount: governed.fileCount } } }));
  writeFileSync(frozenPath, JSON.stringify({ schema: "raven-receipt-verifier-release-identity/2", package: { name: PACKAGE_NAME, version: PACKAGE_VERSION, nodeFloor: NODE_FLOOR, runtimeDependencies: 0, exportMap: EXPECTED_EXPORT_MAP }, toolchain: { npm: PINNED_NPM_VERSION, nodeExecutions: ["v22.18.0", "v24.20.0"] }, upstreamSource: { commit: UPSTREAM_ACCEPTED_COMMIT, tree: UPSTREAM_ACCEPTED_TREE, packageTree: UPSTREAM_ACCEPTED_PACKAGE_TREE }, publicMirror: { repository: PUBLIC_REPOSITORY.replace(/^git\+/, "").replace(/\.git$/, ""), packageDirectory: "packages/verify-js", publicationRef: PUBLICATION_REF, commitBinding: "RAVEN_RELEASE_SHA == GITHUB_SHA == HEAD == freshly-resolved publicationRef^{commit}", treeBinding: "RAVEN_RELEASE_TREE == HEAD^{tree} == freshly-resolved publicationRef^{commit}^{tree}", packageTree: PUBLIC_MIRROR_PACKAGE_TREE }, artifact: actual }));
  const cleanEnv = Object.fromEntries(Object.entries(process.env).filter(([k]) => !/^(npm_config_|NPM_CONFIG_|NODE_OPTIONS|NPM_TOKEN|NODE_AUTH_TOKEN)/i.test(k)));
  const args = { packJsonPath, tarballDir: artifactDir, artifactIdentityPath: handoffPath, frozenIdentityPath: frozenPath, confirmVersion: PACKAGE_VERSION, releaseRef: PUBLICATION_REF, releaseSha: commit, releaseTree: tree, githubRef: PUBLICATION_REF, githubSha: commit, remote: "origin", cwd: repo, governedNpmDir: GOVERNED, inheritedEnvironment: cleanEnv, dryRun: true };
  return { root, tarball: path.join(artifactDir, CANONICAL_TARBALL), actual, args, cleanEnv };
};
const withFixture = (body) => { const f = fixture(); try { return body(f); } finally { rmSync(f.root, { recursive: true, force: true }); } };
const swapped = (tarball) => gzipSync(Buffer.concat([gunzipSync(readFileSync(tarball)), Buffer.alloc(512)]));

// A hostile npm earlier in PATH: truthful preflight, malicious publish, full invocation log.
const hostileNpm = (root) => {
  const bin = path.join(root, "hostile-bin"); mkdirSync(bin);
  const log = path.join(root, "hostile.log");
  writeFileSync(path.join(bin, "npm"), `#!/bin/sh
echo "INVOKED: $*" >> ${JSON.stringify(log)}
case "$1" in
  --version) echo ${PINNED_NPM_VERSION} ;;
  config) echo ${PUBLICATION_REGISTRY}/ ;;
  publish) chmod u+w "$2" 2>/dev/null; printf MUTATED > "$2"; echo "MUTATED $2" >> ${JSON.stringify(log)} ;;
esac
`); chmodSync(path.join(bin, "npm"), 0o755);
  return { bin, log, invocations: () => (existsSync(log) ? readFileSync(log, "utf8") : "") };
};

test("positive control: governed npm tree, CLI and tarball identities are policy-pinned", () => {
  const id = verifyGovernedNpm(GOVERNED);
  assert.equal(id.version, PINNED_NPM_VERSION);
  assert.equal(measureNpmTree(GOVERNED).treeSha256, GOVERNED_NPM.treeSha256);
  assert.equal(sha256(readFileSync(path.join(GOVERNED, "bin/npm-cli.js"))), GOVERNED_NPM.cliSha256);
  assert.equal(run(process.execPath, [path.join(GOVERNED, "bin/npm-cli.js"), "--version"]), PINNED_NPM_VERSION);
  assert.match(GOVERNED_NPM.tarballIntegrity, /^sha512-/);
  assert.equal(Buffer.from(GOVERNED_NPM.tarballSha512, "hex").toString("base64"), GOVERNED_NPM.tarballIntegrity.slice(7));
});

test("positive control + (A): hostile PATH npm is never invoked; governed CLI observes exactly the frozen bytes", () => withFixture((f) => {
  const hostile = hostileNpm(f.root);
  const env = { ...f.cleanEnv, PATH: `${hostile.bin}${path.delimiter}${process.env.PATH}` };
  const result = guardAndPublish({ ...f.args, inheritedEnvironment: env });
  assert.equal(hostile.invocations(), "", "hostile PATH npm must never run");
  assert.equal(result.observed.shasum, f.actual.sha1, "governed CLI must observe the frozen shasum");
  assert.equal(result.observed.totalFiles, String(f.actual.fileCount));
  assert.equal(result.observed.registry.replace(/\/+$/, ""), PUBLICATION_REGISTRY);
  assert.equal(result.governedNpm.treeSha256, GOVERNED_NPM.treeSha256);
  assert.notEqual(result.sealed, f.tarball);
  assert.ok(!result.environment.includes("NODE_OPTIONS"));
  assert.equal(sha256(readFileSync(f.tarball)), f.actual.sha256, "shared tarball untouched");
}));

test("(A2) hostile npm remains uninvoked even when it is the ONLY npm on PATH", () => withFixture((f) => {
  const hostile = hostileNpm(f.root);
  const env = { ...f.cleanEnv, PATH: `${hostile.bin}${path.delimiter}/usr/bin${path.delimiter}/bin` };
  const result = guardAndPublish({ ...f.args, inheritedEnvironment: env });
  assert.equal(hostile.invocations(), "");
  assert.equal(result.observed.shasum, f.actual.sha1);
}));

const tamperedCopy = (root, mutate) => {
  const copy = path.join(root, "npm-copy"); cpSync(GOVERNED, copy, { recursive: true }); mutate(copy); return copy;
};

test("(B) tampered governed npm bytes with the same reported version turn RED before the publisher", () => withFixture((f) => {
  const copy = tamperedCopy(f.root, (dir) => {
    const target = path.join(dir, "node_modules/libnpmpublish/lib/publish.js");
    writeFileSync(target, `${readFileSync(target, "utf8")}\n// attacker\n`);
  });
  assert.equal(run(process.execPath, [path.join(copy, "bin/npm-cli.js"), "--version"]), PINNED_NPM_VERSION, "tampered copy still self-reports the pinned version");
  let calls = 0;
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: copy, publisher: () => { calls += 1; } }), /tree identity/);
  assert.equal(calls, 0);
}));

test("(B2) tampered npm-cli.js with same version string turns RED", () => withFixture((f) => {
  const copy = tamperedCopy(f.root, (dir) => { const t = path.join(dir, "bin/npm-cli.js"); writeFileSync(t, `${readFileSync(t, "utf8")}\n`); });
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: copy, publisher: () => {} }), /governed npm CLI bytes/);
}));

test("(C) npm-cli.js sealed CLI substituted after seal is caught at the boundary", () => withFixture((f) => {
  const copy = tamperedCopy(f.root, () => {});
  let calls = 0;
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: copy,
    beforePublish: (_sealed, governed) => { chmodSync(governed.cli, 0o600); writeFileSync(governed.cli, `${readFileSync(governed.cli, "utf8")}\n// swapped\n`); },
    publisher: () => { calls += 1; } }), /CLI bytes|tree identity|changed before publication|sealed/);
  assert.equal(calls, 0);
}));

test("(D) NODE_OPTIONS in the inherited environment is refused, and never reaches the publisher", () => withFixture((f) => {
  const marker = path.join(f.root, "node-options-marker");
  const hook = path.join(f.root, "hook.cjs"); writeFileSync(hook, `require("fs").writeFileSync(${JSON.stringify(marker)}, "pwned");`);
  assert.throws(() => guardAndPublish({ ...f.args, inheritedEnvironment: { ...f.cleanEnv, NODE_OPTIONS: `--require ${hook}` }, publisher: () => {} }), /NODE_OPTIONS/);
  assert.ok(!existsSync(marker));
  const env = buildPublishEnvironment({ inherited: { ...f.cleanEnv, NODE_OPTIONS: "--require x" }, home: "/h", tmp: "/t", nodeBinDir: "/n" });
  assert.ok(!("NODE_OPTIONS" in env));
}));

test("(E) NPM_CONFIG_REGISTRY / npm_config_registry overrides turn RED", () => withFixture((f) => {
  for (const name of ["NPM_CONFIG_REGISTRY", "npm_config_registry", "NPM_CONFIG_USERCONFIG", "npm_config_globalconfig", "NPM_CONFIG_PREFIX"]) {
    assert.throws(() => guardAndPublish({ ...f.args, inheritedEnvironment: { ...f.cleanEnv, [name]: "https://registry.example.invalid/" }, publisher: () => {} }), new RegExp(name));
  }
}));

test("(F) malicious .npmrc in HOME, in the artifact directory and in the checkout cannot redirect publication", () => withFixture((f) => {
  const home = path.join(f.root, "home"); mkdirSync(home);
  writeFileSync(path.join(home, ".npmrc"), "registry=https://registry.example.invalid/\n//registry.example.invalid/:_authToken=x\n");
  writeFileSync(path.join(f.args.tarballDir, ".npmrc"), "registry=https://registry.example.invalid/\n");
  writeFileSync(path.join(f.args.cwd, ".npmrc"), "registry=https://registry.example.invalid/\n");
  let seen = null;
  const result = guardAndPublish({ ...f.args, inheritedEnvironment: { ...f.cleanEnv, HOME: home }, publisher: (sealed, ctx) => {
    seen = ctx;
    const out = run(process.execPath, [ctx.cli, "config", "get", "registry", "--registry", `${PUBLICATION_REGISTRY}/`, "--userconfig", path.join(ctx.sealDir, "governed-userconfig"), "--globalconfig", path.join(ctx.sealDir, "governed-globalconfig")], { cwd: ctx.sealDir, env: ctx.env });
    return { registry: out };
  } });
  assert.equal(result.observed.registry.replace(/\/+$/, ""), PUBLICATION_REGISTRY);
  assert.notEqual(seen.env.HOME, home, "publisher HOME must be a private directory, not the inherited one");
  assert.ok(!existsSync(path.join(seen.env.HOME, ".npmrc")));
  // and the real governed publisher (dry-run) still targets the pinned registry
  const real = guardAndPublish({ ...f.args, inheritedEnvironment: { ...f.cleanEnv, HOME: home } });
  assert.equal(real.observed.registry.replace(/\/+$/, ""), PUBLICATION_REGISTRY);
}));

test("(G) user/global config substitution through environment or files is refused or ignored", () => withFixture((f) => {
  assert.throws(() => guardAndPublish({ ...f.args, inheritedEnvironment: { ...f.cleanEnv, NPM_CONFIG_GLOBALCONFIG: "/tmp/evil" }, publisher: () => {} }), /NPM_CONFIG_GLOBALCONFIG/);
  assert.throws(() => guardAndPublish({ ...f.args, inheritedEnvironment: { ...f.cleanEnv, XDG_CONFIG_HOME: "/tmp/evil" }, publisher: () => {} }), /XDG_CONFIG_HOME/);
  assert.throws(() => guardAndPublish({ ...f.args, inheritedEnvironment: { ...f.cleanEnv, PREFIX: "/tmp/evil" }, publisher: () => {} }), /PREFIX/);
  const result = guardAndPublish({ ...f.args, publisher: (sealed, ctx) => ({ userconfig: ctx.env.HOME }) });
  assert.ok(result.observed.userconfig.startsWith(tmpdir()) || result.observed.userconfig.includes("raven-sealed-release-"));
}));

test("(H) unexpected publish environment: forbidden classes refuse; everything else is dropped; passthrough is exact", () => withFixture((f) => {
  for (const name of ["NPM_TOKEN", "NODE_AUTH_TOKEN", "NPM_ID_TOKEN", "SIGSTORE_ID_TOKEN", "GIT_CONFIG_COUNT", "HTTPS_PROXY", "https_proxy", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "SSL_CERT_FILE"]) {
    assert.throws(() => assertNoForbiddenEnvironment({ ...f.cleanEnv, [name]: "x" }), new RegExp(name));
  }
  const inherited = { ...f.cleanEnv, ATTACKER_VAR: "x", LD_PRELOAD: "/tmp/evil.so", DYLD_INSERT_LIBRARIES: "/tmp/evil.dylib", SHELL: "/tmp/evil", GITHUB_TOKEN: "ghs_x", GITHUB_ACTIONS: "true", GITHUB_REPOSITORY: "o/r", ACTIONS_ID_TOKEN_REQUEST_URL: "https://t", ACTIONS_ID_TOKEN_REQUEST_TOKEN: "tok" };
  const env = buildPublishEnvironment({ inherited, home: "/h", tmp: "/t", nodeBinDir: "/n" });
  for (const dropped of ["ATTACKER_VAR", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "SHELL", "GITHUB_TOKEN"]) assert.ok(!(dropped in env), `${dropped} must be dropped`);
  for (const kept of ["GITHUB_ACTIONS", "GITHUB_REPOSITORY", "ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN"]) assert.equal(env[kept], inherited[kept]);
  assert.equal(env.PATH, ["/n", "/usr/bin", "/bin"].join(path.delimiter));
  assert.equal(env.HOME, "/h");
  const allowed = new Set(["PATH", "HOME", "TMPDIR", "TMP", "TEMP", ...PUBLISH_ENV_PASSTHROUGH]);
  for (const name of Object.keys(env)) assert.ok(allowed.has(name), `${name} is outside the allowlist`);
}));

test("(I) second/alternate npm CLI path — symlinked dir, different install, missing dir — turns RED", () => withFixture((f) => {
  const link = path.join(f.root, "npm-link"); symlinkSync(GOVERNED, link);
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: link, publisher: () => {} }), /is a symlink/);
  const other = tamperedCopy(f.root, (dir) => rmSync(path.join(dir, "node_modules/abbrev"), { recursive: true, force: true }));
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: other, publisher: () => {} }), /file count|tree identity/);
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: path.join(f.root, "nope"), publisher: () => {} }), /missing/);
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: undefined, publisher: () => {} }), /required/);
  const cliLink = tamperedCopy(f.root, (dir) => { const t = path.join(dir, "bin/npm-cli.js"); const real = `${t}.real`; copyFileSync(t, real); rmSync(t); symlinkSync(real, t); });
  assert.throws(() => guardAndPublish({ ...f.args, governedNpmDir: cliLink, publisher: () => {} }), /regular file|file count|tree/);
}));

test("(J) sealed artifact altered before publisher invocation is refused; altered during is UNCERTAIN", () => withFixture((f) => {
  let calls = 0;
  assert.throws(() => guardAndPublish({ ...f.args, beforePublish: (sealed) => { chmodSync(sealed, 0o600); writeFileSync(sealed, swapped(f.tarball)); }, publisher: () => { calls += 1; } }), /sealed tarball changed before/);
  assert.equal(calls, 0);
  assert.throws(() => guardAndPublish({ ...f.args, publisher: (sealed) => { chmodSync(sealed, 0o600); writeFileSync(sealed, swapped(f.tarball)); return {}; } }), /UNCERTAIN/);
  assert.throws(() => guardAndPublish({ ...f.args, publisher: () => ({ shasum: "0".repeat(40) }) }), /UNCERTAIN/);
  assert.throws(() => guardAndPublish({ ...f.args, publisher: () => ({ registry: "https://registry.example.invalid" }) }), /published to/);
}));

test("(K) governed npm tarball identity: one changed byte or wrong size turns RED", () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-gnpm-tgz-"));
  try {
    const good = path.join(scratch, "good.tgz");
    const tgz = process.env.RAVEN_GOVERNED_NPM_TGZ;
    if (tgz && existsSync(tgz)) {
      copyFileSync(tgz, good); assert.doesNotThrow(() => verifyGovernedNpmTarball(good));
      const bad = Buffer.from(readFileSync(good)); bad[bad.length - 5] ^= 1; writeFileSync(path.join(scratch, "bad.tgz"), bad);
      assert.throws(() => verifyGovernedNpmTarball(path.join(scratch, "bad.tgz")), /sha256/);
    }
    writeFileSync(path.join(scratch, "short.tgz"), Buffer.alloc(10));
    assert.throws(() => verifyGovernedNpmTarball(path.join(scratch, "short.tgz")), /size/);
  } finally { rmSync(scratch, { recursive: true, force: true }); }
});

test("(L) publisher is invoked as governed Node + absolute governed CLI, from the sealed directory", () => withFixture((f) => {
  let ctx = null;
  guardAndPublish({ ...f.args, publisher: (sealed, c) => { ctx = { ...c, sealed }; return {}; } });
  assert.ok(ctx.execRoot && ctx.cli.startsWith(ctx.execRoot + path.sep));
  assert.ok(ctx.cli.includes("/bin/") && ctx.cli.endsWith("cli.js"));
  assert.ok(!ctx.cli.startsWith(path.resolve(GOVERNED) + path.sep));
  assert.ok(path.isAbsolute(ctx.cli));
  assert.equal(path.dirname(ctx.sealed), ctx.sealDir);
  assert.ok(ctx.env.PATH.startsWith(path.dirname(process.execPath)));
}));

// ---------------- v6 TOCTOU execution seal ----------------
test("CONTROL no-op: sealed publish path remains GREEN", () => withFixture((f) => {
  let ctx = null;
  const result = guardAndPublish({ ...f.args, publisher: (sealed, c) => { ctx = c; return { shasum: f.actual.sha1, registry: "https://registry.npmjs.org", totalFiles: String(f.actual.fileCount) }; } });
  assert.ok(ctx.cli.startsWith(ctx.execRoot + path.sep), "cli must be under private exec seal");
  assert.equal(result.governedNpm.sealed, true);
  assert.equal(result.governedNpm.treeSha256, GOVERNED_NPM.treeSha256);
  assert.ok(!ctx.cli.startsWith(path.resolve(GOVERNED) + path.sep));
}));

test("M-TOCTOU-04 mutate original AFTER seal stays GREEN", () => withFixture((f) => {
  const copy = tamperedCopy(f.root, () => {});
  let ctx = null;
  const result = guardAndPublish({ ...f.args, governedNpmDir: copy,
    beforePublish: () => {
      const target = path.join(copy, "node_modules/libnpmpublish/lib/publish.js");
      writeFileSync(target, `${readFileSync(target, "utf8")}\n// after-seal source mutation\n`);
    },
    publisher: (sealed, c) => { ctx = c; return { shasum: f.actual.sha1, registry: "https://registry.npmjs.org" }; },
  });
  assert.ok(ctx.cli.startsWith(ctx.execRoot + path.sep));
  assert.equal(path.resolve(ctx.sourcePackageDir), path.resolve(copy));
  assert.equal(result.governedNpm.treeSha256, GOVERNED_NPM.treeSha256);
}));

test("M-TOCTOU-02 mutate sealed CLI after seal turns RED", () => withFixture((f) => {
  let calls = 0;
  assert.throws(() => guardAndPublish({ ...f.args,
    beforePublish: (_s, governed) => {
      chmodSync(governed.cli, 0o600);
      writeFileSync(governed.cli, `${readFileSync(governed.cli, "utf8")}\n`);
    },
    publisher: () => { calls += 1; },
  }), /CLI bytes|tree identity|sealed|changed before publication/);
  assert.equal(calls, 0);
}));

test("M-TOCTOU-03 mutate sealed tree file after seal turns RED", () => withFixture((f) => {
  let calls = 0;
  assert.throws(() => guardAndPublish({ ...f.args,
    beforePublish: (_s, governed) => {
      const target = path.join(governed.packageDir, "node_modules/libnpmpublish/lib/publish.js");
      chmodSync(path.dirname(target), 0o700);
      chmodSync(target, 0o600);
      writeFileSync(target, `${readFileSync(target, "utf8")}\n// sealed tree mutate\n`);
    },
    publisher: () => { calls += 1; },
  }), /tree identity|sealed|changed before publication/);
  assert.equal(calls, 0);
}));

test("M-TOCTOU-05 seal refuses symlink in source tree", () => withFixture((f) => {
  const sym = path.join(f.root, "sym"); cpSync(GOVERNED, sym, { recursive: true });
  const victim = path.join(sym, "node_modules/libnpmpublish/lib/publish.js");
  const bak = `${victim}.real`;
  renameSync(victim, bak);
  symlinkSync(path.basename(bak), victim);
  assert.throws(() => sealGovernedNpmExecution(sym, path.join(f.root, "out-sym")), /link|symlink/i);
}));

test("M-TOCTOU-06 seal refuses hardlink surprise", () => withFixture((f) => {
  const hard = path.join(f.root, "hard"); cpSync(GOVERNED, hard, { recursive: true });
  const a = path.join(hard, "node_modules/libnpmpublish/lib/publish.js");
  const b = path.join(hard, "node_modules/libnpmpublish/lib/publish.js.hardlink");
  linkSync(a, b);
  assert.throws(() => copyGovernedNpmTreeIntoSeal(hard, path.join(f.root, "out-hard")), /hardlink/);
}));

test("M-TOCTOU-07 seal refuses FIFO", () => withFixture((f) => {
  const fifoRoot = path.join(f.root, "fifo"); cpSync(GOVERNED, fifoRoot, { recursive: true });
  const fifoPath = path.join(fifoRoot, "node_modules/libnpmpublish/lib/fifo-node");
  const made = spawnSync("mkfifo", [fifoPath], { encoding: "utf8" });
  if (made.status !== 0) {
    assert.ok(true, "mkfifo unavailable on this host; covered by non-regular refusal path in unit copy");
    return;
  }
  assert.throws(() => sealGovernedNpmExecution(fifoRoot, path.join(f.root, "out-fifo")), /non-regular|fifo|FIFO/i);
}));

test("M-TOCTOU-08 publisher cli is under seal and not the shared tree", () => withFixture((f) => {
  let ctx = null;
  guardAndPublish({ ...f.args, publisher: (_s, c) => { ctx = c; } });
  assert.ok(ctx.execRoot);
  assert.ok(ctx.cli.startsWith(ctx.execRoot + path.sep));
  assert.ok(ctx.cli.includes(`${path.sep}package${path.sep}bin${path.sep}`));
  assert.notEqual(path.resolve(path.dirname(path.dirname(ctx.cli))), path.resolve(GOVERNED));
}));

test("M-TOCTOU-09 sealed exec tree destroyed after publish", () => withFixture((f) => {
  let execRoot = null;
  guardAndPublish({ ...f.args, publisher: (_s, c) => { execRoot = c.execRoot; } });
  assert.ok(execRoot);
  assert.ok(!existsSync(execRoot), "execution seal must be destroyed in finally");
}));

test("M-TOCTOU-01 concurrent writer on shared source cannot pwn sealed publish", () => withFixture((f) => {
  const copy = tamperedCopy(f.root, () => {});
  const target = path.join(copy, "node_modules/libnpmpublish/lib/publish.js");
  const marker = path.join(f.root, "TOCTOU_PWNED");
  const pristine = readFileSync(target);
  const mutated = Buffer.concat([Buffer.from(`require("fs").writeFileSync(${JSON.stringify(marker)}, "pwned");\n`), pristine]);
  const pristinePath = path.join(f.root, "pristine.bin");
  const mutatedPath = path.join(f.root, "mutated.bin");
  writeFileSync(pristinePath, pristine);
  writeFileSync(mutatedPath, mutated);
  const racer = spawn(process.execPath, ["-e", `
    const fs = require("node:fs");
    const a = fs.readFileSync(${JSON.stringify(pristinePath)});
    const b = fs.readFileSync(${JSON.stringify(mutatedPath)});
    const t = ${JSON.stringify(target)};
    for (;;) { try { fs.writeFileSync(t, b); fs.writeFileSync(t, a); } catch {} }
  `], { stdio: "ignore" });
  try {
    let wins = 0;
    for (let i = 0; i < 20; i++) {
      rmSync(marker, { force: true });
      try {
        guardAndPublish({ ...f.args, governedNpmDir: copy, dryRun: true });
      } catch {
        // refuse-closed on a mid-copy/measure race against source is acceptable
      }
      if (existsSync(marker)) wins += 1;
    }
    assert.equal(wins, 0, "mutated shared publish.js must never execute");
  } finally {
    racer.kill();
    try { writeFileSync(target, pristine); } catch {}
  }
}));

test("M-TOCTOU-12 re-measure mismatch on sealed copy refuses", () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-toctou-remeasure-"));
  try {
    const dest = path.join(scratch, "package");
    copyGovernedNpmTreeIntoSeal(GOVERNED, dest);
    const target = path.join(dest, "node_modules/libnpmpublish/lib/publish.js");
    chmodSync(target, 0o600);
    writeFileSync(target, `${readFileSync(target, "utf8")}\n`);
    assert.throws(() => verifyGovernedNpm(dest), /tree identity/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
