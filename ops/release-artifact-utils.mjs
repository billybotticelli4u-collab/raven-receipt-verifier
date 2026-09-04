import { createHash } from "node:crypto";
import {
  lstatSync,
  readFileSync,
  readdirSync,
  realpathSync,
} from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";

import {
  CANONICAL_TARBALL,
  EXPECTED_EXPORT_MAP,
  EXPECTED_FILES_ALLOWLIST,
  EXPECTED_PACKAGE_FILES,
  NODE_FLOOR,
  PACKAGE_NAME,
  PACKAGE_VERSION,
  PUBLIC_BUGS,
  PUBLIC_HOMEPAGE,
  PUBLIC_REPOSITORY,
} from "./release-policy.mjs";

export const parseArgs = (argv) => {
  const parsed = {};
  for (let index = 2; index < argv.length; index += 2) {
    const arg = argv[index];
    const value = argv[index + 1];
    if (!arg?.startsWith("--") || value === undefined || value.startsWith("--")) {
      throw new Error(`invalid argument near ${arg ?? "<missing>"}`);
    }
    const key = arg.slice(2);
    if (Object.hasOwn(parsed, key)) throw new Error(`duplicate --${key}`);
    parsed[key] = value;
  }
  return parsed;
};

export const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

export const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, { encoding: "utf8", ...options });
  if (result.status !== 0) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join("");
    throw new Error(`${command} ${args.join(" ")} exited ${result.status}${detail ? `\n${detail}` : ""}`);
  }
  return result.stdout.trim();
};

export const git = (...args) => run("git", args);
export const gitAt = (cwd, ...args) => run("git", args, { cwd });
export const npmCommand = () => (process.platform === "win32" ? "npm.cmd" : "npm");

const hash = (algorithm, bytes, encoding = "hex") =>
  createHash(algorithm).update(bytes).digest(encoding);

const fail = (failures, label, expected, actual) => {
  if (JSON.stringify(expected) !== JSON.stringify(actual)) {
    failures.push(`${label}: expected ${JSON.stringify(expected)}, actual ${JSON.stringify(actual)}`);
  }
};

const assertSafeMembers = (rawMembers) => {
  const failures = [];
  const normalized = [];
  for (const member of rawMembers) {
    if (
      !member.startsWith("package/") ||
      member.endsWith("/") ||
      member.includes("\\") ||
      member.split("/").includes("..") ||
      path.posix.isAbsolute(member)
    ) {
      failures.push(`unsafe or non-file tar member: ${member}`);
      continue;
    }
    normalized.push(member.slice("package/".length));
  }
  fail(failures, "actual tar member inventory", EXPECTED_PACKAGE_FILES, normalized.sort());
  if (failures.length) throw new Error(failures.join("\n"));
  return normalized.sort();
};

const tarString = (block, start, length) => {
  const field = block.subarray(start, start + length);
  const end = field.indexOf(0);
  return field.subarray(0, end < 0 ? field.length : end).toString("utf8");
};

const tarOctal = (block, start, length, label) => {
  const raw = tarString(block, start, length).trim();
  if (!/^[0-7]+$/.test(raw)) throw new Error(`invalid tar ${label}: ${JSON.stringify(raw)}`);
  const value = Number.parseInt(raw, 8);
  if (!Number.isSafeInteger(value) || value < 0) throw new Error(`unsafe tar ${label}: ${raw}`);
  return value;
};

const parseTarEntries = (decoded) => {
  const entries = [];
  let offset = 0;
  let ended = false;
  while (offset + 512 <= decoded.length) {
    const block = decoded.subarray(offset, offset + 512);
    if (block.every((byte) => byte === 0)) {
      ended = true;
      break;
    }
    const expectedChecksum = tarOctal(block, 148, 8, "checksum");
    let checksum = 0;
    for (let index = 0; index < 512; index += 1) {
      checksum += index >= 148 && index < 156 ? 0x20 : block[index];
    }
    if (checksum !== expectedChecksum) throw new Error(`tar header checksum mismatch at block ${offset / 512}`);
    const name = tarString(block, 0, 100);
    const prefix = tarString(block, 345, 155);
    const member = prefix ? `${prefix}/${name}` : name;
    const type = block[156];
    if (type !== 0 && type !== 0x30) {
      throw new Error(`non-regular tar member ${member}: type ${String.fromCharCode(type)}`);
    }
    const size = tarOctal(block, 124, 12, "member size");
    const contentStart = offset + 512;
    const contentEnd = contentStart + size;
    if (contentEnd > decoded.length) throw new Error(`truncated tar member: ${member}`);
    entries.push({ member, size, bytes: decoded.subarray(contentStart, contentEnd) });
    offset = contentStart + Math.ceil(size / 512) * 512;
  }
  if (!ended) throw new Error("tar archive has no zero-block terminator");
  for (let index = offset; index < decoded.length; index += 1) {
    if (decoded[index] !== 0) throw new Error("tar archive contains non-zero data after terminator");
  }
  return entries;
};

export const resolveCanonicalTarball = ({ packJsonPath, tarballDir }) => {
  const resolvedDir = path.resolve(tarballDir);
  const dirStat = lstatSync(resolvedDir);
  if (!dirStat.isDirectory() || dirStat.isSymbolicLink()) {
    throw new Error(`artifact directory is not a real directory: ${resolvedDir}`);
  }

  const packRecords = readJson(path.resolve(packJsonPath));
  if (!Array.isArray(packRecords) || packRecords.length !== 1) {
    throw new Error(`pack JSON must contain exactly one record; saw ${packRecords?.length ?? "non-array"}`);
  }
  const packed = packRecords[0];
  if (packed.filename !== CANONICAL_TARBALL) {
    throw new Error(`noncanonical tarball filename: ${packed.filename ?? "<missing>"}`);
  }

  const tgzFiles = readdirSync(resolvedDir).filter((entry) => entry.endsWith(".tgz")).sort();
  if (JSON.stringify(tgzFiles) !== JSON.stringify([CANONICAL_TARBALL])) {
    throw new Error(`artifact directory must contain exactly ${CANONICAL_TARBALL}; saw ${tgzFiles.join(", ") || "none"}`);
  }

  const tarball = path.join(resolvedDir, CANONICAL_TARBALL);
  const tarStat = lstatSync(tarball);
  if (!tarStat.isFile() || tarStat.isSymbolicLink()) {
    throw new Error(`canonical tarball is not a regular file: ${tarball}`);
  }
  if (path.dirname(realpathSync(tarball)) !== realpathSync(resolvedDir)) {
    throw new Error(`canonical tarball escapes artifact directory: ${tarball}`);
  }
  return { packed, tarball, tarballDir: resolvedDir };
};

const verifyInstalledManifest = (manifest) => {
  const failures = [];
  fail(failures, "installed name", PACKAGE_NAME, manifest.name);
  fail(failures, "installed version", PACKAGE_VERSION, manifest.version);
  fail(failures, "installed repository", {
    type: "git",
    url: PUBLIC_REPOSITORY,
    directory: "packages/verify-js",
  }, manifest.repository);
  fail(failures, "installed homepage", PUBLIC_HOMEPAGE, manifest.homepage);
  fail(failures, "installed bugs", PUBLIC_BUGS, manifest.bugs);
  fail(failures, "installed engines.node", NODE_FLOOR, manifest.engines?.node);
  fail(failures, "installed runtime dependencies", {}, manifest.dependencies ?? {});
  fail(failures, "installed export map", EXPECTED_EXPORT_MAP, manifest.exports);
  fail(failures, "installed files allowlist", EXPECTED_FILES_ALLOWLIST, manifest.files);
  if (JSON.stringify(manifest).includes("-launch" + "guard")) {
    failures.push("installed package metadata references the private monorepo");
  }
  if (failures.length) throw new Error(failures.join("\n"));
};

export const measureReleaseArtifact = ({ packJsonPath, tarballDir }) => {
  const { packed, tarball } = resolveCanonicalTarball({ packJsonPath, tarballDir });
  const compressed = readFileSync(tarball);
  const decoded = gunzipSync(compressed);
  const entries = parseTarEntries(decoded);
  const members = assertSafeMembers(entries.map(({ member }) => member));
  const files = entries
    .map(({ member, size, bytes }) => ({ relative: member.slice("package/".length), size, bytes }))
    .sort((left, right) => left.relative < right.relative ? -1 : left.relative > right.relative ? 1 : 0);
  const actualFiles = files.map(({ relative, size, bytes }) => ({
    path: relative,
    size,
    sha256: hash("sha256", bytes),
  }));
  const extractedNames = actualFiles.map(({ path: filePath }) => filePath);
  if (JSON.stringify(extractedNames) !== JSON.stringify(EXPECTED_PACKAGE_FILES)) {
    throw new Error(`extracted member inventory differs: ${JSON.stringify(extractedNames)}`);
  }
  const packageJsonEntry = files.find(({ relative }) => relative === "package.json");
  const manifest = JSON.parse(packageJsonEntry.bytes.toString("utf8"));
  verifyInstalledManifest(manifest);
  const unpackedBytes = actualFiles.reduce((total, file) => total + file.size, 0);
  return {
    packed,
    tarball,
    actual: {
      filename: CANONICAL_TARBALL,
      compressedBytes: compressed.length,
      sha1: hash("sha1", compressed),
      sha256: hash("sha256", compressed),
      sha512: hash("sha512", compressed),
      integrity: `sha512-${hash("sha512", compressed, "base64")}`,
      decodedTarBytes: decoded.length,
      decodedTarSha256: hash("sha256", decoded),
      unpackedBytes,
      fileCount: actualFiles.length,
      files: actualFiles,
    },
    manifest,
    members,
  };
};

export const comparePackMetadataToActual = ({ packed, actual }) => {
  const failures = [];
  fail(failures, "pack name", PACKAGE_NAME, packed.name);
  fail(failures, "pack version", PACKAGE_VERSION, packed.version);
  fail(failures, "pack filename", actual.filename, packed.filename);
  fail(failures, "pack entryCount", actual.fileCount, packed.entryCount);
  fail(failures, "pack size", actual.compressedBytes, packed.size);
  fail(failures, "pack unpackedSize", actual.unpackedBytes, packed.unpackedSize);
  fail(failures, "pack shasum", actual.sha1, packed.shasum);
  fail(failures, "pack integrity", actual.integrity, packed.integrity);
  const packFiles = [...(packed.files ?? [])]
    .map(({ path: filePath, size }) => ({ path: filePath, size }))
    .sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
  const actualFiles = actual.files.map(({ path: filePath, size }) => ({ path: filePath, size }));
  fail(failures, "pack file records", actualFiles, packFiles);
  if (failures.length) throw new Error(failures.join("\n"));
};

export const compareActualToFrozen = ({ actual, frozenArtifact }) => {
  const failures = [];
  for (const key of [
    "filename",
    "compressedBytes",
    "sha1",
    "sha256",
    "sha512",
    "integrity",
    "decodedTarBytes",
    "decodedTarSha256",
    "unpackedBytes",
    "fileCount",
    "files",
  ]) {
    fail(failures, `frozen artifact ${key}`, frozenArtifact?.[key], actual[key]);
  }
  if (failures.length) throw new Error(failures.join("\n"));
};

export const compareActualToHandoff = ({ actual, handoff }) => {
  const failures = [];
  for (const key of [
    "filename",
    "compressedBytes",
    "sha1",
    "sha256",
    "sha512",
    "integrity",
    "decodedTarBytes",
    "decodedTarSha256",
    "unpackedBytes",
    "fileCount",
    "files",
  ]) {
    fail(failures, `handoff artifact ${key}`, actual[key], handoff?.artifact?.[key]);
  }
  if (failures.length) throw new Error(failures.join("\n"));
};

export const assertSameActualIdentity = (before, after) => {
  compareActualToHandoff({ actual: before, handoff: { artifact: after } });
};
