// Whole-workflow structural allowlist + file-identity pin. Closes the job-
// and workflow-level survivor class found reviewing 4a9c4669 (J1–J14, H5):
// keys outside step identity — needs:, defaults:, env:, runs-on, container:,
// strategy, concurrency, dispatch-input default: — and a byte-level pin so any
// YAML change at all is a reviewed policy change.
import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  parseWorkflowShape,
  scanInvokedPublicationHelpers,
  validateWorkflow,
  validateWorkflowIdentity,
  validateWorkflowText,
} from "./publication-policy.mjs";
import { EXPECTED_WORKFLOW_SHAPE, WORKFLOW_PATH, WORKFLOW_SHA256 } from "./release-policy.mjs";
import { assertPinnedWorkflow } from "./publish-exact-release.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const WORKFLOW = readFileSync(path.join(ROOT, WORKFLOW_PATH), "utf8");
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const structuralRed = (label, mutated) => {
  const failures = validateWorkflowText(mutated);
  assert.ok(failures.length > 0, `${label} survived the structural allowlist`);
  assert.ok(failures.every((f) => !/workflow identity sha256/.test(f)), `${label} must be caught structurally, not only by the file hash`);
  return failures;
};
const identityRed = (label, mutated) => {
  const failures = validateWorkflowIdentity(mutated);
  assert.ok(failures.length > 0, `${label} survived the file identity pin`);
};
const inJob = (job, from, to) => {
  const start = WORKFLOW.indexOf(`\n  ${job}:`);
  const at = WORKFLOW.indexOf(from, start);
  assert.ok(start >= 0 && at >= 0, `anchor missing for ${job}: ${from}`);
  return WORKFLOW.slice(0, at) + to + WORKFLOW.slice(at + from.length);
};

test("positive control: reviewed workflow satisfies shape, structure and identity", () => {
  assert.deepEqual(validateWorkflow(WORKFLOW), []);
  assert.equal(sha256(WORKFLOW), WORKFLOW_SHA256);
  const shape = parseWorkflowShape(WORKFLOW);
  assert.deepEqual(shape, EXPECTED_WORKFLOW_SHAPE);
  assert.deepEqual(shape.topKeys, ["name", "on", "permissions", "env", "jobs"]);
  assert.deepEqual(shape.jobs.map((j) => j.name), ["source-gate", "package-artifact", "tarball-gate", "publish"]);
});

test("M35 (J1/J2/J10) needs: removal or retarget on any job turns RED", () => {
  structuralRed("J1", inJob("publish", "    needs: tarball-gate\n", ""));
  structuralRed("J2", inJob("publish", "    needs: tarball-gate\n", "    needs: source-gate\n"));
  structuralRed("J10", inJob("package-artifact", "    needs: source-gate\n", ""));
  structuralRed("tarball-gate needs", inJob("tarball-gate", "    needs: package-artifact\n", "    needs: source-gate\n"));
});

test("M36 (J3/J4/J9) defaults.run shell / working-directory at job or workflow level turns RED", () => {
  structuralRed("J3", inJob("publish", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    defaults:\n      run:\n        working-directory: attacker\n"));
  structuralRed("J4", inJob("publish", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    defaults:\n      run:\n        shell: bash --rcfile /tmp/evil {0}\n"));
  structuralRed("J9", WORKFLOW.replace("\npermissions:\n", "\ndefaults:\n  run:\n    shell: bash --rcfile /tmp/evil {0}\npermissions:\n"));
});

test("M37 (J5/J6) env injection at job or workflow level turns RED", () => {
  structuralRed("J5", inJob("publish", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    env:\n      NODE_OPTIONS: --require /tmp/evil.js\n"));
  structuralRed("J6", WORKFLOW.replace('env:\n  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n', 'env:\n  RAVEN_PINNED_NPM_VERSION: "11.18.0"\n  NODE_OPTIONS: --require /tmp/evil.js\n'));
  structuralRed("env on gate", inJob("source-gate", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    env:\n      NPM_CONFIG_IGNORE_SCRIPTS: false\n"));
});

test("M38 (J7/J8/J12/J13) runner, container, strategy and concurrency changes turn RED", () => {
  structuralRed("J7", inJob("publish", "    runs-on: ubuntu-latest\n", "    runs-on: self-hosted\n"));
  structuralRed("J8", inJob("publish", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    container: attacker/image@sha256:0000\n"));
  structuralRed("services", inJob("publish", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    services:\n      proxy:\n        image: attacker/proxy\n"));
  structuralRed("J12", inJob("publish", "    runs-on: ubuntu-latest\n", "    runs-on: ubuntu-latest\n    strategy:\n      matrix:\n        x: [1, 2]\n"));
  structuralRed("matrix drift", inJob("source-gate", 'node-version: ["22.18.0", "24"]', 'node-version: ["22.18.0", "24", "20"]'));
  structuralRed("J13", WORKFLOW.replace("\npermissions:\n", "\nconcurrency:\n  group: pub\n  cancel-in-progress: true\npermissions:\n"));
  structuralRed("timeout", inJob("publish", "    timeout-minutes: 20\n", "    timeout-minutes: 600\n"));
});

test("M39 (J14) dispatch input default / extra input / extra top-level key turns RED", () => {
  structuralRed("J14", WORKFLOW.replace("      release_ref:\n        description:", "      release_ref:\n        default: refs/heads/attacker\n        description:"));
  structuralRed("extra input", WORKFLOW.replace("      confirm_version:\n", "      registry:\n        description: x\n        required: false\n      confirm_version:\n"));
  structuralRed("extra top-level key", WORKFLOW.replace("\npermissions:\n", "\nrun-name: attacker\npermissions:\n"));
  structuralRed("jobs reordered", (() => {
    const a = WORKFLOW.indexOf("\n  tarball-gate:"); const b = WORKFLOW.indexOf("\n  publish:");
    return WORKFLOW.slice(0, a) + WORKFLOW.slice(b) + WORKFLOW.slice(a, b);
  })());
  structuralRed("job renamed", WORKFLOW.replace("\n  tarball-gate:\n", "\n  tarball-check:\n").replace("needs: tarball-gate", "needs: tarball-check"));
  structuralRed("extra job", WORKFLOW.replace("\n  publish:\n", "\n  swap:\n    needs: tarball-gate\n    runs-on: ubuntu-latest\n    permissions:\n      contents: read\n    steps:\n      - run: echo swap\n\n  publish:\n"));
});

test("M40 file identity pin: whitespace-only, comment-only, or trailing-newline edits turn RED on identity", () => {
  const ws = WORKFLOW.replace("# v4.2.2\n", "# v4.2.2 \n");
  assert.deepEqual(validateWorkflowText(ws), [], "whitespace edit is structurally invisible by design");
  identityRed("whitespace", ws);
  identityRed("leading comment", `# attacker\n${WORKFLOW}`);
  identityRed("trailing newline", `${WORKFLOW}\n`);
  identityRed("action version comment", WORKFLOW.replace("# v4.2.2", "# v4.9.9"));
  assert.ok(validateWorkflow(ws).length > 0, "combined validator must include the identity pin");
});

test("M41 runtime: publish wrapper refuses when the checked-out workflow is not the pinned bytes", () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-wf-pin-"));
  try {
    const target = path.join(scratch, WORKFLOW_PATH);
    mkdirSync(path.dirname(target), { recursive: true });
    copyFileSync(path.join(ROOT, WORKFLOW_PATH), target);
    assert.doesNotThrow(() => assertPinnedWorkflow(scratch));
    writeFileSync(target, `${WORKFLOW}\n`);
    assert.throws(() => assertPinnedWorkflow(scratch), /workflow/);
    rmSync(target);
    assert.throws(() => assertPinnedWorkflow(scratch), /workflow/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("M42 (H5) invoked helper that writes npm configuration turns RED", () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-h5-"));
  try {
    mkdirSync(path.join(scratch, "ops"));
    for (const [name, body] of [
      ["npmrc.mjs", 'import fs from "node:fs";\nfs.appendFileSync(process.env.HOME + "/.npmrc", "registry=https://x");\n'],
      ["config.mjs", 'import { spawnSync } from "node:child_process";\nspawnSync("npm", ["config", "set", "registry", "https://x"]);\n'],
      ["env.mjs", 'process.env.npm_config_registry = "https://x";\n'],
    ]) {
      writeFileSync(path.join(scratch, "ops", name), body);
      const failures = scanInvokedPublicationHelpers({ root: scratch, workflow: `run: node ops/${name}\n` });
      assert.ok(failures.some((f) => f.includes(name)), `${name} must be named`);
    }
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("M43 positive-control non-vacuity: structural validator still passes a whitespace-shifted copy", () => {
  // Proves the structural layer is independent of the byte pin (so the
  // structural mutations above are not vacuously RED via the hash).
  assert.deepEqual(validateWorkflowText(WORKFLOW.replace(/\n$/, "\n\n")), []);
});
