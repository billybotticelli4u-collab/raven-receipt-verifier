// Generates the machine identity for the single npm pack output. This file is
// evidence for review and artifact handoff; it is not the governed frozen
// release/release-identity.json authorization record.
import { writeFileSync } from "node:fs";
import path from "node:path";
import {
  assertCustomerPackage,
  decodedTarIdentity,
  git,
  npmCommand,
  parseArgs,
  resolveTarballPath,
  run,
} from "./release-artifact-utils.mjs";

const args = parseArgs(process.argv);
const packJsonPath = path.resolve(args["pack-json"]);
const tarballDir = path.resolve(args["tarball-dir"]);
const outPath = path.resolve(args.out);
const expectedNpm = args["expected-npm"];
const { packed, tarball } = resolveTarballPath({ packJsonPath, tarballDir });
const { packedFiles } = assertCustomerPackage({ packed, tarball });
const decoded = decodedTarIdentity(tarball);
const npmVersion = run(npmCommand(), ["--version"]).stdout.trim();

if (expectedNpm && npmVersion !== expectedNpm) {
  console.error(`REFUSED artifact identity: npm version expected ${expectedNpm}, actual ${npmVersion}`);
  process.exit(1);
}

const identity = {
  schema: "raven-receipt-verifier-artifact-handoff/1",
  note: "REHEARSAL OR CI HANDOFF EVIDENCE ONLY unless separately named by an Owner authorization. This records the single npm pack output carried to verification and publication.",
  package: {
    name: packed.name,
    version: packed.version,
    filename: packed.filename,
    fileCount: packed.entryCount,
    packedSize: packed.size,
    unpackedSize: packed.unpackedSize,
    shasum: packed.shasum,
    integrity: packed.integrity,
    decodedTarBytes: decoded.decodedTarBytes,
    decodedTarSha256: decoded.decodedTarSha256,
    runtimeDependencies: 0,
    files: packedFiles,
  },
  source: {
    commit: git("rev-parse", "HEAD"),
    tree: git("rev-parse", "HEAD^{tree}"),
    ref: process.env.GITHUB_REF ?? null,
  },
  toolchain: {
    node: process.version,
    npm: npmVersion,
  },
};

writeFileSync(outPath, `${JSON.stringify(identity, null, 2)}\n`, "utf8");
console.log(`wrote release artifact identity: ${outPath}`);
console.log(`decoded tar SHA-256: ${decoded.decodedTarSha256}`);
