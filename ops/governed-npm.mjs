import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, realpathSync } from "node:fs";
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

export const governedNodeIdentity = () => ({
  version: process.version,
  execPath: process.execPath,
  execPathSha256: sha("sha256", readFileSync(process.execPath)),
});

export const assertGovernedNodeLine = () => {
  if (!GOVERNED_NPM.nodeLines.test(process.version)) throw new Error(`Node ${process.version} is not a governed line`);
};
