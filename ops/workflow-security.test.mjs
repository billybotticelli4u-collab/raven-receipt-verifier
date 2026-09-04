// Permanent security controls on the publication ceremony. These assertions are
// the reason the workflow cannot quietly become unsafe: every property below
// was chosen because losing it would allow an unreviewed or unapproved publish.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const WF_PATH = fileURLToPath(new URL("../.github/workflows/verify-js-publish.yml", import.meta.url));
const wf = readFileSync(WF_PATH, "utf8");
const sourceGateJob = wf.slice(wf.indexOf("\n  source-gate:"), wf.indexOf("\n  package-artifact:"));
const packageArtifactJob = wf.slice(wf.indexOf("\n  package-artifact:"), wf.indexOf("\n  tarball-gate:"));
const tarballGateJob = wf.slice(wf.indexOf("\n  tarball-gate:"), wf.indexOf("\n  publish:"));
const publishJob = wf.slice(wf.indexOf("\n  publish:"));
const unprotectedJobs = `${sourceGateJob}\n${packageArtifactJob}\n${tarballGateJob}`;

test("workflow security: instrument is live (positive control)", () => {
  assert.ok(wf.includes("name: verify-js publish"), "workflow file must be readable and named");
  assert.ok(sourceGateJob.length > 200, "source gate job must be locatable for scoped assertions");
  assert.ok(packageArtifactJob.length > 200, "package artifact job must be locatable for scoped assertions");
  assert.ok(tarballGateJob.length > 200, "tarball gate job must be locatable for scoped assertions");
  assert.ok(publishJob.length > 200, "publish job must be locatable for scoped assertions");
});

test("publication requires OIDC id-token", () => {
  assert.match(publishJob, /permissions:\s*\n\s+contents: read\s*\n\s+id-token: write/,
    "publish job must request id-token: write for npm trusted publishing");
});

test("publication is gated on a protected environment", () => {
  assert.match(publishJob, /^\s{4}environment:\s*npm-release\s*$/m,
    "publish job must run in the protected npm-release environment");
});

test("no token-based npm authentication anywhere", () => {
  for (const forbidden of [/NPM_TOKEN/, /NODE_AUTH_TOKEN/, /_authToken/, /npm\s+login/, /npm\s+adduser/, /secrets\.NPM/]) {
    assert.ok(!forbidden.test(wf), `token-based npm auth is forbidden: ${forbidden}`);
  }
});

test("workflow never publishes on push, pull_request, or an arbitrary branch", () => {
  const onBlock = wf.slice(wf.indexOf("\non:"), wf.indexOf("\npermissions:"));
  assert.ok(!/\bpush:/.test(onBlock), "push trigger is forbidden");
  assert.ok(!/\bpull_request:/.test(onBlock), "pull_request trigger is forbidden");
  assert.ok(/workflow_dispatch:/.test(onBlock), "manual dispatch is the only permitted trigger");
  for (const requiredInput of ["release_ref", "release_sha", "release_tree", "confirm_version"]) {
    assert.match(onBlock, new RegExp(`\\n\\s{6}${requiredInput}:`), `${requiredInput} must be an explicit dispatch input`);
  }
});

test("pack happens once in the secretless artifact job, then publish ships that tarball", () => {
  assert.equal((wf.match(/^\s+npm pack\b/gm) || []).length, 1, "workflow must execute npm pack exactly once");
  assert.match(packageArtifactJob, /npm pack --json --pack-destination "\$RUNNER_TEMP\/release-package"/,
    "package artifact job must create the only tarball");
  assert.match(packageArtifactJob, /actions\/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02/,
    "single pack output must be uploaded as a handoff artifact");
  assert.match(tarballGateJob, /actions\/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093/,
    "tarball gate must download the handoff artifact");
  assert.match(publishJob, /actions\/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093/,
    "publish job must download the handoff artifact");
  assert.ok(!/\bnpm pack\b/.test(sourceGateJob), "source gate must not pack");
  assert.ok(!/\bnpm pack\b/.test(tarballGateJob), "tarball gate must not repack");
  assert.ok(!/\bnpm pack\b/.test(publishJob), "publish job must not repack");
  assert.match(publishJob, /npm publish "\$tarball" --provenance --access public/,
    "must publish the exact packed tarball with provenance");
  assert.ok(!/npm publish\s*(--|$)/m.test(publishJob.replace(/npm publish "\$tarball"[^\n]*/g, "")),
    "no bare `npm publish` from source may exist");
});

test("publication refuses on release-SHA drift and on tarball identity drift", () => {
  for (const job of [sourceGateJob, packageArtifactJob, tarballGateJob, publishJob]) {
    assert.match(job, /ops\/verify-release-ref\.mjs/, "every job must verify release ref/SHA/tree after checkout");
  }
  assert.match(packageArtifactJob, /ops\/verify-release-artifact\.mjs/, "pack job must verify the frozen identity before upload");
  assert.match(tarballGateJob, /ops\/verify-release-artifact\.mjs/, "tarball gate must verify the downloaded identity");
  assert.match(publishJob, /ops\/verify-release-artifact\.mjs/, "publish job must verify frozen tarball identity before publish");
});

test("unprotected gates are secretless and carry no OIDC", () => {
  assert.ok(!/id-token/.test(unprotectedJobs), "unapproved jobs must not hold id-token");
  assert.ok(!/environment:/.test(unprotectedJobs), "unapproved jobs must not run in the protected environment");
  assert.match(sourceGateJob, /"22\.18\.0", "24"/, "source gate must run the exact declared Node lines");
  assert.match(tarballGateJob, /"22\.18\.0", "24"/, "tarball gate must run the exact declared Node lines");
});

test("all package-critical jobs install and assert the same pinned npm CLI", () => {
  assert.match(wf, /RAVEN_PINNED_NPM_VERSION: "11\.18\.0"/, "the npm CLI pin must be explicit");
  for (const job of [sourceGateJob, packageArtifactJob, tarballGateJob, publishJob]) {
    assert.match(job, /npm install --global "npm@\$\{RAVEN_PINNED_NPM_VERSION\}"/,
      "job must install the pinned npm CLI");
    assert.match(job, /ops\/npm-version-gate\.mjs "\$\{RAVEN_PINNED_NPM_VERSION\}"/,
      "job must assert the pinned npm CLI before critical work");
  }
});

test("workflow never defaults Raven signer trust from /pubkey or mutates production trust", () => {
  assert.ok(!/\/pubkey/.test(wf), "publication workflow must not fetch /pubkey as trust input");
  assert.ok(!/production-pins|signer|trusted-keys|RAVEN_TRUSTED_KEYS/.test(wf),
    "publication workflow must not alter production signer or trust-pin configuration");
});
