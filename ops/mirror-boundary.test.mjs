// Permanent mirror-boundary controls. This repository is the PUBLIC release
// source: nothing private from the development monorepo may appear here, and
// the customer tarball must never expose non-customer surfaces.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const manifest = JSON.parse(readFileSync(join(ROOT, "packages/verify-js/package.json"), "utf8"));
const MIRROR_URL = "https://github.com/billybotticelli4u-collab/raven-receipt-verifier";

const walk = (dir, acc = []) => {
  for (const e of readdirSync(dir)) {
    if (e === ".git" || e === "node_modules" || e === "dist") continue;
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, acc);
    else acc.push(p.slice(ROOT.length));
  }
  return acc;
};
const files = walk(ROOT);

test("mirror boundary: instrument is live (positive control)", () => {
  assert.ok(files.length > 50, `expected a populated mirror, saw ${files.length} files`);
  assert.ok(files.includes("packages/verify-js/package.json"), "package manifest must be present");
});

test("mirror boundary: no private monorepo classes are present", () => {
  const forbidden = [
    /(^|\/)operator\//i, /(^|\/)docs\/raven\//i, /(^|\/)apps\/raven-site\//i,
    /outreach/i, /\bcrm\b/i, /pilot[_-]?kit/i, /prospect/i,
    /\.env($|\.)/i, /production-pins/i, /authorizations?\.jsonl/i,
    /vercel/i, /\.npmrc$/i, /id_rsa|\.pem$|\.key$/i,
  ];
  const hits = files.filter((f) => forbidden.some((re) => re.test(f)));
  assert.deepEqual(hits, [], `private-class paths leaked into the public mirror: ${hits.join(", ")}`);
});

test("mirror boundary: no file content references the private repository", () => {
  // Two files legitimately NAME the private repo: the SJ1 manifest guard and
  // this boundary suite. They are exempt only while every occurrence sits in a
  // negative assertion — an exemption that cannot be used to smuggle content.
  // This scanner must name its own needle, so it is exempt outright.
  const SCANNER = "ops/mirror-boundary.test.mjs";
  const GUARDS = new Set(["packages/verify-js/test/releaseManifest.test.ts"]);
  const offenders = [];
  for (const f of files) {
    if (!/\.(json|md|ts|mjs|js|yml|yaml|txt)$/.test(f)) continue;
    const body = readFileSync(join(ROOT, f), "utf8");
    if (f === SCANNER) continue;
    if (!body.includes("-launchguard")) continue;
    if (!GUARDS.has(f)) { offenders.push(f); continue; }
    const lines = body.split("\n").filter((l) => l.includes("-launchguard"));
    for (const l of lines) {
      if (!/(must not|!JSON\.stringify|GUARDS|forbidden|never)/.test(l)) offenders.push(`${f} (non-guard use)`);
    }
  }
  assert.deepEqual(offenders, [], `public mirror names the private monorepo in: ${offenders.join(", ")}`);
});

test("package repository metadata points at this public mirror, never the private repo", () => {
  assert.ok(manifest.repository, "repository metadata is required for npm provenance");
  assert.equal(manifest.repository.type, "git");
  assert.equal(manifest.repository.url, `git+${MIRROR_URL}.git`);
  assert.equal(manifest.repository.directory, "packages/verify-js");
  assert.ok(!JSON.stringify(manifest.repository).includes("-launchguard"),
    "repository must not point strangers at the private monorepo");
  assert.ok(!JSON.stringify(manifest.bugs).includes("-launchguard"));
});

test("customer tarball never ships proposed/EVM/key-manifest surfaces", () => {
  const shipped = manifest.files.join("\n");
  for (const forbidden of ["proposed", "receiptEvmV1", "verifyReceiptEvmV1", "keyManifest", "Evm", "evm"]) {
    assert.ok(!shipped.includes(forbidden),
      `files[] allowlist would ship a non-customer surface: ${forbidden}`);
  }
  assert.deepEqual(Object.keys(manifest.exports), ["."],
    "the package export map must expose only the customer root entrypoint");
  const manifestText = JSON.stringify(manifest);
  for (const forbidden of ["proposed", "receiptEvmV1", "verifyReceiptEvmV1", "keyManifest", "Evm", "evm"]) {
    assert.ok(!manifestText.includes(forbidden),
      `package manifest would expose a non-customer surface: ${forbidden}`);
  }
  assert.equal(manifest.files.filter((f) => f.startsWith("dist/")).length, 11);
});

test("package stays dependency-free and provenance-enabled", () => {
  assert.deepEqual(manifest.dependencies, {});
  assert.equal(manifest.publishConfig.provenance, true);
  assert.equal(manifest.publishConfig.access, "public");
  assert.equal(manifest.engines.node, ">=22.18");
});
