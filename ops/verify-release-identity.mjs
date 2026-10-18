// Refuses publication unless the freshly packed artifact matches the frozen
// package/source identity AND an independently supplied decoded-tar pin.
//
// Release anchor = SHA-256 of the gunzip-decoded tar stream (ustar/pax bytes),
// NOT the gzip/.tgz container. Print tgz digests elsewhere for the record;
// never gate on tgz shasum / npm integrity / packedSize.
//
// CLI (all required):
//   node ops/verify-release-identity.mjs \
//     --pack-json <npm-pack-json> \
//     --tarball <path-to-the-exact-.tgz> \
//     --confirm-version <semver> \
//     --expected-decoded-tar-sha256 <hex64> \
//     --expected-member-count <int>
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";

const usage = () => {
  console.error(
    "usage: node ops/verify-release-identity.mjs --pack-json P --tarball T --confirm-version V --expected-decoded-tar-sha256 HEX --expected-member-count N",
  );
  process.exit(2);
};

const args = process.argv.slice(2);
const get = (flag) => {
  const i = args.indexOf(flag);
  if (i < 0 || i + 1 >= args.length) return undefined;
  return args[i + 1];
};

const packJsonPath = get("--pack-json");
const tarballPath = get("--tarball");
const confirmVersion = get("--confirm-version");
const expectedTar = get("--expected-decoded-tar-sha256");
const expectedMembersRaw = get("--expected-member-count");

if (!packJsonPath || !tarballPath || !confirmVersion || !expectedTar || expectedMembersRaw === undefined) {
  usage();
}
if (!/^[0-9a-f]{64}$/i.test(expectedTar)) {
  console.error("REFUSED expected-decoded-tar-sha256: must be 64 hex chars");
  process.exit(1);
}
const expectedMembers = Number(expectedMembersRaw);
if (!Number.isInteger(expectedMembers) || expectedMembers < 1) {
  console.error("REFUSED expected-member-count: must be a positive integer (independently pinned; not inferred)");
  process.exit(1);
}

const frozenDoc = JSON.parse(readFileSync(new URL("../release/release-identity.json", import.meta.url), "utf8"));
const frozen = frozenDoc.package;
const frozenSource = frozenDoc.source;
const packed = JSON.parse(readFileSync(packJsonPath, "utf8"))[0];

const drift = [];
const check = (field, want, got) => {
  if (want !== got) drift.push([field, want, got]);
};

check("name", frozen.name, packed.name);
check("version", frozen.version, packed.version);
check("confirm_version", frozen.version, confirmVersion);

// Source-identity: frozen correspondence must be present and well-formed.
if (!frozenSource || typeof frozenSource !== "object") {
  drift.push(["source", "object", frozenSource === undefined ? "missing" : typeof frozenSource]);
} else {
  for (const k of ["mirrorRepository", "packageDirectory", "derivedFromPrivateMain", "derivedFromPrivateTree"]) {
    if (typeof frozenSource[k] !== "string" || frozenSource[k].length < 1) {
      drift.push([`source.${k}`, "non-empty string", frozenSource[k]]);
    }
  }
  check("source.packageDirectory", "packages/verify-js", frozenSource.packageDirectory);
  if (!String(frozenSource.mirrorRepository).includes("raven-receipt-verifier")) {
    drift.push(["source.mirrorRepository", "raven-receipt-verifier mirror URL", frozenSource.mirrorRepository]);
  }
}

const tgz = readFileSync(tarballPath);
let tarBytes;
try {
  tarBytes = gunzipSync(tgz);
} catch (e) {
  console.error(`REFUSED tarball: not a gzip/.tgz (${e && e.message ? e.message : e})`);
  process.exit(1);
}

const measuredTar = createHash("sha256").update(tarBytes).digest("hex");
check("decoded_tar_sha256", expectedTar.toLowerCase(), measuredTar);

// Member count from the decoded tar (ustar/pax). Explicit pin; not taken from npm entryCount alone.
const memberCount = countTarMembers(tarBytes);
check("member_count", expectedMembers, memberCount);

// Record-only (never gate): tgz sha256 + npm shasum/integrity may drift across toolchains.
const tgzSha256 = createHash("sha256").update(tgz).digest("hex");
console.log(
  JSON.stringify({
    recordOnly: {
      tgzSha256,
      npmShasum: packed.shasum,
      npmIntegrity: packed.integrity,
      packedSize: packed.size,
      npmEntryCount: packed.entryCount,
    },
    measured: { decodedTarSha256: measuredTar, memberCount },
  }),
);

if (drift.length) {
  for (const [f, want, got] of drift) console.error(`REFUSED ${f}: frozen/want=${want} measured/got=${got}`);
  process.exit(1);
}
console.log("release identity matches (decoded-tar pin + package/source checks); publication may proceed");

/** Count tar members in a ustar/pax stream (512-byte headers). */
function countTarMembers(buf) {
  let offset = 0;
  let count = 0;
  const block = 512;
  while (offset + block <= buf.length) {
    const header = buf.subarray(offset, offset + block);
    if (header.every((b) => b === 0)) break; // end-of-archive zero block
    const sizeOct = header.subarray(124, 136).toString("utf8").replace(/\0.*$/, "").trim();
    const size = sizeOct ? parseInt(sizeOct, 8) : 0;
    if (Number.isNaN(size) || size < 0) {
      throw new Error(`invalid tar size field at offset ${offset}`);
    }
    count += 1;
    const dataBlocks = Math.ceil(size / block);
    offset += block + dataBlocks * block;
  }
  return count;
}
