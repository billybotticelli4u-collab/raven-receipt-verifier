import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { scanInvokedPublicationHelpers, validateWorkflowText } from "./publication-policy.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const WORKFLOW_PATH = path.join(ROOT, ".github/workflows/verify-js-publish.yml");
const workflow = readFileSync(WORKFLOW_PATH, "utf8");

const expectWorkflowRed = (label, mutated) => {
  const failures = validateWorkflowText(mutated);
  assert.ok(failures.length > 0, `${label} unexpectedly survived workflow policy`);
};

test("positive control: current workflow satisfies every structural policy", () => {
  assert.deepEqual(validateWorkflowText(workflow), []);
  assert.deepEqual(scanInvokedPublicationHelpers({ root: ROOT, workflow }), []);
});

test("M1 wrong npm version is refused before package work", () => {
  const result = spawnSync(process.execPath, [path.join(ROOT, "ops/npm-version-gate.mjs"), "11.17.0"], {
    cwd: ROOT,
    encoding: "utf8",
  });
  assert.notEqual(result.status, 0);
  assert.match(result.stderr, /REFUSED npm version/);
});

test("M7 second direct pack turns RED", () => {
  expectWorkflowRed("M7", workflow.replace(
    "          npm pack --json --pack-destination",
    "          npm pack --json\n          npm pack --json --pack-destination",
  ));
});

test("M8 hidden second pack behind an invoked helper turns RED", () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-hidden-pack-"));
  try {
    mkdirSync(path.join(scratch, "ops"));
    writeFileSync(
      path.join(scratch, "ops/hidden-repack.mjs"),
      'import { spawnSync } from "node:child_process";\nspawnSync("npm", ["pack"]);\n',
    );
    const failures = scanInvokedPublicationHelpers({
      root: scratch,
      workflow: "run: node ops/hidden-repack.mjs\n",
    });
    assert.ok(failures.some((failure) => failure.includes("hidden-repack.mjs")));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("M8 tar reconstruction behind an invoked helper turns RED", () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-hidden-tar-"));
  try {
    mkdirSync(path.join(scratch, "ops"));
    writeFileSync(
      path.join(scratch, "ops/hidden-tar.mjs"),
      'import { spawnSync } from "node:child_process";\nspawnSync("tar", ["-czf", "replacement.tgz", "package"]);\n',
    );
    const failures = scanInvokedPublicationHelpers({
      root: scratch,
      workflow: "run: node ops/hidden-tar.mjs\n",
    });
    assert.ok(failures.some((failure) => failure.includes("hidden-tar.mjs")));
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("M19 removal of the final guarded verify-to-publish wrapper turns RED", () => {
  expectWorkflowRed("M19", workflow.replace(
    "node ops/publish-exact-release.mjs",
    "node ops/verify-release-artifact.mjs",
  ));
});

test("M20 publishing a source directory instead of the exact tarball turns RED", () => {
  expectWorkflowRed("M20", workflow.replace(
    "node ops/publish-exact-release.mjs",
    "npm publish packages/verify-js",
  ));
});

test("M21 contents:write on package-artifact turns RED", () => {
  const marker = "  package-artifact:\n";
  const index = workflow.indexOf(marker);
  const mutated = workflow.slice(0, index) + workflow.slice(index).replace("      contents: read", "      contents: write");
  expectWorkflowRed("M21", mutated);
});

test("M22 id-token authority on tarball-gate turns RED", () => {
  const marker = "  tarball-gate:\n";
  const index = workflow.indexOf(marker);
  const mutated = workflow.slice(0, index) + workflow.slice(index).replace(
    "      contents: read",
    "      contents: read\n      id-token: write",
  );
  expectWorkflowRed("M22", mutated);
});

test("M23 removal of the protected publication environment turns RED", () => {
  expectWorkflowRed("M23", workflow.replace("    environment: npm-release\n", ""));
});

test("secret/token use and persisted checkout credentials turn RED", () => {
  expectWorkflowRed("secret use", workflow.replace("permissions:\n  contents: read", "permissions:\n  contents: read\nenv:\n  NPM_TOKEN: ${{ secrets.NPM_TOKEN }}"));
  expectWorkflowRed("credential persistence", workflow.replace("persist-credentials: false", "persist-credentials: true"));
});

test("manual dispatch, exact inputs, immutable action pins, and one OIDC holder stay mandatory", () => {
  expectWorkflowRed("push trigger", workflow.replace("  workflow_dispatch:", "  push:\n  workflow_dispatch:"));
  expectWorkflowRed("missing SHA input", workflow.replace("      release_sha:", "      omitted_release_sha:"));
  expectWorkflowRed("mutable action ref", workflow.replace(/actions\/checkout@[0-9a-f]{40}/, "actions/checkout@main"));
  expectWorkflowRed("second OIDC holder", workflow.replace("      contents: read\n    strategy:", "      contents: read\n      id-token: write\n    strategy:"));
});
