// Release-packet pins for raven-receipt-verifier (SJ1 PR C).
//
// The manifest is the public face of the canonical verifier on npm. These
// pins encode the owner-ratified release decisions: the verified Node floor,
// deliberate ESM-only format, tree-shaking metadata, provenance, and the SJ1
// invariant that a stranger must never be pointed at the private monorepo.

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const pkgDir = join(dirname(fileURLToPath(import.meta.url)), "..");
const manifest = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
const lock = JSON.parse(readFileSync(join(pkgDir, "package-lock.json"), "utf8"));

test("release manifest: ratified name, verified Node floor", () => {
  assert.equal(manifest.name, "raven-receipt-verifier");
  // 2026-07-21 release plan: the verified minimum is 22.18; lower only after
  // the packed-artifact matrix passes on a proposed lower floor.
  assert.equal(manifest.engines?.node, ">=22.18");
  assert.equal(
    lock.packages?.[""]?.engines?.node,
    manifest.engines.node,
    "package-lock root engine must agree with the published manifest",
  );
  assert.deepEqual(manifest.dependencies, {}, "customer verifier must have zero runtime dependencies");
});

test("release manifest: deliberate ESM-only is stated, tree-shaking marked", () => {
  assert.equal(manifest.type, "module");
  assert.equal(manifest.sideEffects, false);
  // Deliberate ESM-only: no require condition, and the README must say why
  // (require(esm) is supported on the declared Node floor).
  assert.equal(manifest.exports?.["."]?.require, undefined);
  const readme = readFileSync(join(pkgDir, "README.md"), "utf8");
  assert.match(readme, /ESM-only/i);
  assert.match(readme, /22\.18/);
});

test("release manifest: package files pin the customer runtime closure", () => {
  assert.deepEqual(manifest.files, [
    "dist/canonicalDataSnapshot.*",
    "dist/canonicalJson.*",
    "dist/detect.*",
    "dist/index.*",
    "dist/outcomeProjection.*",
    "dist/receiptRules.*",
    "dist/receiptV1.*",
    "dist/solanaAddress.*",
    "dist/trustAnchor.*",
    "dist/verifyReceiptV1.*",
    "dist/verifyReceiptV1ForSubject.*",
    "README.md",
    "LICENSE",
    "SECURITY.md",
  ]);
});

test("release manifest: provenance and stranger-reachable support routes", () => {
  assert.equal(manifest.publishConfig?.access, "public");
  assert.equal(manifest.publishConfig?.provenance, true);
  assert.ok(manifest.bugs, "bugs route required — a stranger must have somewhere to report");
  // SJ1 invariant: no step of the public path may require the private repo.
  assert.ok(
    !JSON.stringify(manifest.repository ?? "").includes("-launchguard"),
    "repository must not point strangers at the private monorepo",
  );
  assert.ok(!JSON.stringify(manifest.bugs).includes("-launchguard"), "bugs must not point at the private monorepo");
});

test("shipped SECURITY.md references the durable RFC 9116 route", () => {
  // The tarball forbids public disclosure; the private route it names must be
  // the durable one that actually exists on the public surface, not a page
  // section that can drift. The site suite pins the route's existence.
  const security = readFileSync(join(pkgDir, "SECURITY.md"), "utf8");
  assert.ok(security.includes("/.well-known/security.txt"), "SECURITY.md must name the RFC 9116 route");
  assert.match(security, /never (include|share|send|paste)/i);
  assert.match(security, /do not open\s+public issues/i);
});

test("README pins the trust-bootstrap contract separately from npm provenance", () => {
  const readme = readFileSync(join(pkgDir, "README.md"), "utf8");
  assert.match(readme, /npm provenance authenticates package\/source lineage/i);
  assert.match(readme, /does not tell you which Raven signer key/i);
  assert.match(readme, /authenticated Raven commercial\/onboarding\s+handoff/i);
  assert.match(readme, /exact package identity/i);
  assert.match(readme, /exact version/i);
  assert.match(readme, /exact package integrity/i);
  assert.match(readme, /embedded production anchor is the package pin/i);
  assert.match(readme, /\/pubkey/i);
  assert.match(readme, /security page/i);
  assert.match(readme, /discovery and cross-check/i);
  assert.match(readme, /keyId.*consistency/i);
  assert.match(readme, /not authenticity/i);
});
