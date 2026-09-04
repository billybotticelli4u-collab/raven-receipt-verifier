// Verifies the uploaded package handoff before publication. It compares the
// exact tarball, npm pack JSON, generated handoff identity, and governed frozen
// release identity. Any drift exits before `npm publish`.
import path from "node:path";
import {
  assertCustomerPackage,
  decodedTarIdentity,
  git,
  parseArgs,
  readJson,
  resolveTarballPath,
} from "./release-artifact-utils.mjs";

const args = parseArgs(process.argv);
const packJsonPath = path.resolve(args["pack-json"]);
const tarballDir = path.resolve(args["tarball-dir"]);
const artifactIdentityPath = path.resolve(args["artifact-identity"]);
const frozenIdentityPath = path.resolve(args["frozen-identity"] ?? "release/release-identity.json");
const confirmVersion = args["confirm-version"];
const expectedNpm = args["expected-npm"];
const { packed, tarball } = resolveTarballPath({ packJsonPath, tarballDir });
const artifact = readJson(artifactIdentityPath);
const frozen = readJson(frozenIdentityPath).package;
const decoded = decodedTarIdentity(tarball);
const failures = [];

const compare = (label, expected, actual) => {
  if (expected !== actual) {
    failures.push(`${label}: expected ${expected}, actual ${actual}`);
  }
};

try {
  assertCustomerPackage({ packed, tarball });
} catch (error) {
  failures.push(...(error.failures ?? [error.message]));
}

compare("name", frozen.name, packed.name);
compare("version", frozen.version, packed.version);
compare("fileCount", frozen.fileCount, packed.entryCount);
compare("packedSize", frozen.packedSize, packed.size);
compare("unpackedSize", frozen.unpackedSize, packed.unpackedSize);
compare("shasum", frozen.shasum, packed.shasum);
compare("integrity", frozen.integrity, packed.integrity);
compare("runtimeDependencies", frozen.runtimeDependencies, 0);

if (confirmVersion) {
  compare("confirm_version", frozen.version, confirmVersion);
}

compare("artifact.name", artifact.package?.name, packed.name);
compare("artifact.version", artifact.package?.version, packed.version);
compare("artifact.filename", artifact.package?.filename, packed.filename);
compare("artifact.fileCount", artifact.package?.fileCount, packed.entryCount);
compare("artifact.packedSize", artifact.package?.packedSize, packed.size);
compare("artifact.unpackedSize", artifact.package?.unpackedSize, packed.unpackedSize);
compare("artifact.shasum", artifact.package?.shasum, packed.shasum);
compare("artifact.integrity", artifact.package?.integrity, packed.integrity);
compare("artifact.decodedTarBytes", artifact.package?.decodedTarBytes, decoded.decodedTarBytes);
compare("artifact.decodedTarSha256", artifact.package?.decodedTarSha256, decoded.decodedTarSha256);
compare("artifact.source.commit", artifact.source?.commit, git("rev-parse", "HEAD"));
compare("artifact.source.tree", artifact.source?.tree, git("rev-parse", "HEAD^{tree}"));

if (expectedNpm) {
  compare("artifact.toolchain.npm", expectedNpm, artifact.toolchain?.npm);
}

if (failures.length) {
  for (const failure of failures) {
    console.error(`REFUSED release artifact: ${failure}`);
  }
  process.exit(1);
}

console.log("release artifact matches frozen identity and handoff record");
console.log(`tarball: ${tarball}`);
console.log(`decoded tar SHA-256: ${decoded.decodedTarSha256}`);
