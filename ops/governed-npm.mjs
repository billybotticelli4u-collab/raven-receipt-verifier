import { createHash } from "node:crypto";
import {
  chmodSync,
  closeSync,
  fchmodSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeSync,
} from "node:fs";
import path from "node:path";

import { GOVERNED_NPM } from "./release-policy.mjs";

const sha = (algorithm, bytes) => createHash(algorithm).update(bytes).digest("hex");

// Canonical content identity of an extracted npm package tree: every regular
// file's path and SHA-256, sorted, hashed. Symlinks, devices and anything
// that is not a plain file or directory are refused outright.
export const measureNpmTree = (root) => {
  const lines = [];
  let fileCount = 0;
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const full = path.join(dir, entry.name);
      const stat = lstatSync(full);
      if (stat.isSymbolicLink()) throw new Error(`governed npm tree contains a symlink: ${full}`);
      if (stat.isDirectory()) { walk(full); continue; }
      if (!stat.isFile()) throw new Error(`governed npm tree contains a non-regular entry: ${full}`);
      fileCount += 1;
      lines.push(`${path.relative(root, full).split(path.sep).join("/")}\0${sha("sha256", readFileSync(full))}\n`);
    }
  };
  walk(root);
  lines.sort();
  return { fileCount, treeSha256: sha("sha256", lines.join("")) };
};

export const verifyGovernedNpmTarball = (tarballPath) => {
  const bytes = readFileSync(tarballPath);
  const failures = [];
  if (bytes.length !== GOVERNED_NPM.tarballBytes) failures.push(`governed npm tarball size ${bytes.length} != ${GOVERNED_NPM.tarballBytes}`);
  if (sha("sha256", bytes) !== GOVERNED_NPM.tarballSha256) failures.push("governed npm tarball sha256 mismatch");
  if (sha("sha512", bytes) !== GOVERNED_NPM.tarballSha512) failures.push("governed npm tarball sha512 mismatch");
  if (failures.length) throw new Error(failures.join("\n"));
  return { bytes: bytes.length, sha256: GOVERNED_NPM.tarballSha256, sha512: GOVERNED_NPM.tarballSha512 };
};

// The ONLY way the ceremony decides an npm CLI is trustworthy: the package
// directory is a real directory, its bin/npm-cli.js is a real file with the
// pinned SHA-256, its package.json names npm@<pinned>, and the whole extracted
// tree hashes to the pinned content identity. Version strings printed by the
// program itself are never the anchor.
export const verifyGovernedNpm = (packageDir) => {
  const failures = [];
  const dir = path.resolve(packageDir);
  const dirStat = lstatSync(dir, { throwIfNoEntry: false });
  if (!dirStat) throw new Error(`governed npm directory missing: ${dir}`);
  if (dirStat.isSymbolicLink()) failures.push(`governed npm directory is a symlink: ${dir} -> ${realpathSync(dir)}`);
  else if (!dirStat.isDirectory()) failures.push(`governed npm path is not a directory: ${dir}`);
  const cli = path.join(dir, "bin", "npm-cli.js");
  const cliStat = lstatSync(cli, { throwIfNoEntry: false });
  if (!cliStat || !cliStat.isFile() || cliStat.isSymbolicLink()) failures.push(`governed npm CLI is not a regular file: ${cli}`);
  else if (sha("sha256", readFileSync(cli)) !== GOVERNED_NPM.cliSha256) failures.push("governed npm CLI bytes differ from policy");
  let manifest = null;
  try { manifest = JSON.parse(readFileSync(path.join(dir, "package.json"), "utf8")); } catch { failures.push("governed npm package.json unreadable"); }
  if (manifest && (manifest.name !== GOVERNED_NPM.name || manifest.version !== GOVERNED_NPM.version)) failures.push(`governed npm manifest is ${manifest.name}@${manifest.version}, policy ${GOVERNED_NPM.name}@${GOVERNED_NPM.version}`);
  if (!failures.length) {
    const tree = measureNpmTree(dir);
    if (tree.fileCount !== GOVERNED_NPM.fileCount) failures.push(`governed npm file count ${tree.fileCount} != ${GOVERNED_NPM.fileCount}`);
    if (tree.treeSha256 !== GOVERNED_NPM.treeSha256) failures.push(`governed npm tree identity ${tree.treeSha256} != policy ${GOVERNED_NPM.treeSha256}`);
  }
  if (failures.length) throw new Error(failures.join("\n"));
  return { packageDir: dir, cli, name: GOVERNED_NPM.name, version: GOVERNED_NPM.version, cliSha256: GOVERNED_NPM.cliSha256, treeSha256: GOVERNED_NPM.treeSha256, fileCount: GOVERNED_NPM.fileCount };
};

export const copyGovernedNpmTreeIntoSeal = (sourceRoot, destRoot) => {
  const srcRoot = path.resolve(sourceRoot);
  const dstRoot = path.resolve(destRoot);
  const srcReal = realpathSync(srcRoot);
  const seenInodes = new Map();
  const copyBytes = (from, to, mode) => {
    const bytes = readFileSync(from);
    const fd = openSync(to, "wx", mode & 0o777);
    try {
      writeSync(fd, bytes);
      fchmodSync(fd, mode & 0o777);
    } finally {
      closeSync(fd);
    }
  };
  const walk = (srcDir, dstDir) => {
    for (const entry of readdirSync(srcDir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
      const src = path.join(srcDir, entry.name);
      const dst = path.join(dstDir, entry.name);
      const rel = path.relative(srcRoot, src).split(path.sep).join("/");
      if (entry.name === "." || entry.name === "..") throw new Error("seal traversal entry: " + entry.name);
      if (!rel || rel.startsWith("..") || path.isAbsolute(rel)) throw new Error("seal path escape: " + src);
      const stat = lstatSync(src);
      if (stat.isSymbolicLink()) throw new Error("seal link: " + rel);
      if (stat.isDirectory()) {
        const real = realpathSync(src);
        if (real !== srcReal && !real.startsWith(srcReal + path.sep)) throw new Error("seal realpath escape: " + rel);
        mkdirSync(dst, { mode: 0o700 });
        chmodSync(dst, 0o700);
        walk(src, dst);
        continue;
      }
      if (!stat.isFile()) throw new Error("seal non-regular: " + rel);
      const inodeKey = String(stat.dev) + ":" + String(stat.ino);
      if (seenInodes.has(inodeKey)) throw new Error("seal hardlink: " + rel + " -> " + seenInodes.get(inodeKey));
      seenInodes.set(inodeKey, rel);
      copyBytes(src, dst, 0o400);
      chmodSync(dst, 0o400);
    }
  };
  mkdirSync(dstRoot, { recursive: true, mode: 0o700 });
  chmodSync(dstRoot, 0o700);
  walk(srcRoot, dstRoot);
};

export const freezeGovernedNpmSealTree = (root) => {
  const walk = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      const stat = lstatSync(full);
      if (stat.isSymbolicLink()) throw new Error("seal post-copy link: " + full);
      if (stat.isDirectory()) { walk(full); chmodSync(full, 0o500); continue; }
      if (!stat.isFile()) throw new Error("seal post-copy non-regular: " + full);
      chmodSync(full, 0o400);
    }
  };
  walk(root);
  chmodSync(root, 0o500);
};

export const sealGovernedNpmExecution = (packageDir, sealParent) => {
  const source = verifyGovernedNpm(packageDir);
  mkdirSync(sealParent, { recursive: true, mode: 0o700 });
  chmodSync(sealParent, 0o700);
  const makeTmp = mkdtempSync;
  const sealPrefix = path.join(sealParent, "gexec-");
  const execRoot = makeTmp(sealPrefix, { mode: 0o700 });
  chmodSync(execRoot, 0o700);
  const sealedPackageDir = path.join(execRoot, "package");
  copyGovernedNpmTreeIntoSeal(source.packageDir, sealedPackageDir);
  freezeGovernedNpmSealTree(sealedPackageDir);
  chmodSync(execRoot, 0o700);
  const sealed = verifyGovernedNpm(sealedPackageDir);
  if (sealed.treeSha256 !== GOVERNED_NPM.treeSha256) throw new Error("sealed tree identity mismatch");
  if (sha("sha256", readFileSync(sealed.cli)) !== GOVERNED_NPM.cliSha256) throw new Error("sealed CLI bytes mismatch");
  const expectedCli = path.join(sealedPackageDir, "bin", "npm-cli.js");
  if (sealed.cli !== expectedCli) throw new Error("sealed CLI path escaped package");
  if (!sealed.cli.startsWith(execRoot + path.sep)) throw new Error("sealed CLI outside exec seal");
  return { ...sealed, sourcePackageDir: source.packageDir, execRoot, sealed: true };
};

export const governedNodeIdentity = () => ({
  version: process.version,
  execPath: process.execPath,
  execPathSha256: sha("sha256", readFileSync(process.execPath)),
});

export const assertGovernedNodeLine = () => {
  if (!GOVERNED_NPM.nodeLines.test(process.version)) throw new Error(`Node ${process.version} is not a governed line`);
};
