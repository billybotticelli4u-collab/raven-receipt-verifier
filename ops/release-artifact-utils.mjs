import { createHash } from "node:crypto";
import {
  existsSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  statSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { gunzipSync } from "node:zlib";

export const CUSTOMER_MODULES = [
  "canonicalDataSnapshot",
  "canonicalJson",
  "detect",
  "index",
  "outcomeProjection",
  "receiptRules",
  "receiptV1",
  "solanaAddress",
  "trustAnchor",
  "verifyReceiptV1",
  "verifyReceiptV1ForSubject",
];

export const COMPILED_EXTENSIONS = [".d.ts", ".d.ts.map", ".js", ".js.map"];

export const expectedPackedFiles = () => [
  "LICENSE",
  "README.md",
  "SECURITY.md",
  "package.json",
  ...CUSTOMER_MODULES.flatMap((moduleName) =>
    COMPILED_EXTENSIONS.map((extension) => `dist/${moduleName}${extension}`),
  ),
].sort();

export const parseArgs = (argv) => {
  const parsed = {};
  for (let i = 2; i < argv.length; i += 1) {
    const arg = argv[i];
    if (!arg.startsWith("--")) {
      throw new Error(`unexpected positional argument: ${arg}`);
    }
    const key = arg.slice(2);
    const value = argv[i + 1];
    if (value === undefined || value.startsWith("--")) {
      throw new Error(`missing value for --${key}`);
    }
    parsed[key] = value;
    i += 1;
  }
  return parsed;
};

export const readJson = (filePath) => JSON.parse(readFileSync(filePath, "utf8"));

export const resolveTarballPath = ({ packJsonPath, tarballDir }) => {
  const packed = readJson(packJsonPath)[0];
  if (!packed?.filename) {
    throw new Error(`pack JSON ${packJsonPath} does not name a tarball filename`);
  }
  const tarball = path.resolve(tarballDir, packed.filename);
  if (!existsSync(tarball)) {
    throw new Error(`tarball named by pack JSON does not exist: ${tarball}`);
  }
  return { packed, tarball };
};

export const decodedTarIdentity = (tarball) => {
  const decoded = gunzipSync(readFileSync(tarball));
  return {
    decodedTarBytes: decoded.length,
    decodedTarSha256: createHash("sha256").update(decoded).digest("hex"),
  };
};

export const run = (command, args, options = {}) => {
  const result = spawnSync(command, args, {
    encoding: "utf8",
    ...options,
  });
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`${command} ${args.join(" ")} exited ${result.status}`);
  }
  return result;
};

export const git = (...args) => run("git", args).stdout.trim();

export const npmCommand = () => (process.platform === "win32" ? "npm.cmd" : "npm");

export const extractTarball = (tarball) => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-release-artifact-"));
  run("tar", ["-xzf", tarball, "-C", scratch]);
  return {
    scratch,
    packageRoot: path.join(scratch, "package"),
    cleanup: () => rmSync(scratch, { recursive: true, force: true }),
  };
};

export const walk = (dir, prefix = "", acc = []) => {
  for (const entry of readdirSync(dir)) {
    const absolute = path.join(dir, entry);
    const relative = prefix ? `${prefix}/${entry}` : entry;
    if (statSync(absolute).isDirectory()) {
      walk(absolute, relative, acc);
    } else {
      acc.push(relative);
    }
  }
  return acc;
};

export const assertCustomerPackage = ({ packed, tarball }) => {
  const packedFiles = packed.files.map(({ path: packedPath }) => packedPath).sort();
  const expected = expectedPackedFiles();
  const unexpected = packedFiles.filter((file) => !expected.includes(file));
  const missing = expected.filter((file) => !packedFiles.includes(file));
  const failures = [];

  if (unexpected.length) {
    failures.push(`unexpected packaged files: ${unexpected.join(", ")}`);
  }
  if (missing.length) {
    failures.push(`missing packaged files: ${missing.join(", ")}`);
  }
  if (packedFiles.some((file) => file.startsWith("src/"))) {
    failures.push("raw TypeScript sources are packaged");
  }

  const extracted = extractTarball(tarball);
  try {
    const installedFiles = walk(extracted.packageRoot).sort();
    const manifest = readJson(path.join(extracted.packageRoot, "package.json"));
    const runtimeDependencies = Object.keys(manifest.dependencies ?? {});

    if (runtimeDependencies.length !== 0) {
      failures.push(`runtime dependencies must be zero; got ${runtimeDependencies.join(", ")}`);
    }

    if (manifest.exports === undefined || Object.keys(manifest.exports).join(",") !== ".") {
      failures.push(`only the root export is allowed; got ${Object.keys(manifest.exports ?? {}).join(",") || "<none>"}`);
    }

    const manifestText = JSON.stringify(manifest);
    for (const forbidden of ["proposed", "receiptEvmV1", "verifyReceiptEvmV1", "keyManifest", "Evm", "evm"]) {
      if (manifestText.includes(forbidden)) {
        failures.push(`package manifest exposes a withheld/proposed surface: ${forbidden}`);
      }
    }

    const installedUnexpected = installedFiles
      .filter((file) => file !== "package.json")
      .filter((file) => !expected.includes(file));
    if (installedUnexpected.length) {
      failures.push(`extracted tarball has unexpected files: ${installedUnexpected.join(", ")}`);
    }
  } finally {
    extracted.cleanup();
  }

  if (failures.length) {
    const error = new Error(failures.join("\n"));
    error.failures = failures;
    throw error;
  }

  return { packedFiles };
};
