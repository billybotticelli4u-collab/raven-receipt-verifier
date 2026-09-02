// Permanent security controls on the publication ceremony. These assertions are
// the reason the workflow cannot quietly become unsafe: every property below
// was chosen because losing it would allow an unreviewed or unapproved publish.
import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const WF_PATH = fileURLToPath(new URL("../.github/workflows/verify-js-publish.yml", import.meta.url));
const wf = readFileSync(WF_PATH, "utf8");
const publishJob = wf.slice(wf.indexOf("\n  publish:"));

test("workflow security: instrument is live (positive control)", () => {
  assert.ok(wf.includes("name: verify-js publish"), "workflow file must be readable and named");
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
});

test("publish step ships the packed tarball, never `npm publish` from source", () => {
  assert.match(publishJob, /npm publish "\$tarball" --provenance --access public/,
    "must publish the exact packed tarball with provenance");
  assert.ok(!/npm publish\s*(--|$)/m.test(publishJob.replace(/npm publish "\$tarball"[^\n]*/g, "")),
    "no bare `npm publish` from source may exist");
  assert.equal((wf.match(/npm pack/g) || []).length, 1, "pack exactly once");
});

test("publication refuses on release-SHA drift and on tarball identity drift", () => {
  assert.match(publishJob, /REFUSED: HEAD .*authorized release SHA/, "must refuse on SHA drift");
  assert.match(publishJob, /ops\/verify-release-identity\.mjs/, "must verify frozen tarball identity before publish");
});

test("the gate job is secretless and carries no OIDC", () => {
  const gateJob = wf.slice(wf.indexOf("\n  gate:"), wf.indexOf("\n  publish:"));
  assert.ok(!/id-token/.test(gateJob), "the unapproved gate job must not hold id-token");
  assert.ok(!/environment:/.test(gateJob), "the gate job must not run in the protected environment");
  assert.match(gateJob, /"22\.18\.0", "24"/, "gate must run the exact declared Node lines");
});
