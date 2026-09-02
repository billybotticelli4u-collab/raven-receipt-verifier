// Refuses publication unless the freshly packed tarball matches the frozen
// release identity exactly. Consumed by the publish workflow immediately after
// the single `npm pack`, before `npm publish`.
import { readFileSync } from "node:fs";
const [, , packJsonPath, confirmVersion] = process.argv;
const frozen = JSON.parse(readFileSync(new URL("../release/release-identity.json", import.meta.url), "utf8")).package;
const packed = JSON.parse(readFileSync(packJsonPath, "utf8"))[0];
const checks = [
  ["name", frozen.name, packed.name],
  ["version", frozen.version, packed.version],
  ["fileCount", frozen.fileCount, packed.entryCount],
  ["packedSize", frozen.packedSize, packed.size],
  ["unpackedSize", frozen.unpackedSize, packed.unpackedSize],
  ["shasum", frozen.shasum, packed.shasum],
  ["integrity", frozen.integrity, packed.integrity],
];
const drift = checks.filter(([, want, got]) => want !== got);
if (confirmVersion && confirmVersion !== frozen.version) {
  drift.push(["confirm_version", frozen.version, confirmVersion]);
}
if (drift.length) {
  for (const [f, want, got] of drift) console.error(`REFUSED ${f}: frozen=${want} measured=${got}`);
  process.exit(1);
}
console.log("release identity matches the frozen packet; publication may proceed");
