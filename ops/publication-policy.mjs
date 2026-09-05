import { readFileSync } from "node:fs";
import path from "node:path";

import {
  APPROVED_ACTIONS,
  EXPECTED_JOB_STEPS,
  GOVERNED_NODE_MATRIX,
  GOVERNED_PUBLISH_NODE,
  PINNED_NPM_VERSION,
  PUBLICATION_REGISTRY,
} from "./release-policy.mjs";

const JOB_ORDER = ["source-gate", "package-artifact", "tarball-gate", "publish"];

const sliceJob = (workflow, name, next) => {
  const start = workflow.indexOf(`\n  ${name}:`);
  const end = next ? workflow.indexOf(`\n  ${next}:`, start + 1) : workflow.length;
  if (start < 0 || end < 0) return "";
  return workflow.slice(start, end);
};

const exactPermissions = (job, expectedLines) => {
  const match = job.match(/^    permissions:\n((?:      [^\n]+\n)+)/m);
  if (!match) return false;
  return match[1].trim() === expectedLines.join("\n");
};

// Structural step parser: every `      - ` block under `    steps:` is one
// step. Its identity is the ENTIRE normalised block — uses/run text, with:,
// env:, if:, every key — minus the human-readable name:. Any inserted,
// removed, reordered or edited key on any step changes the identity.
export const stepSignature = (block) => block
  .split("\n")
  .filter((line) => !/^\s+-?\s*name:/.test(line))
  .map((line) => line.replace(/^\s+-\s+/, "").trim())
  .filter(Boolean)
  .join(" ")
  .replace(/\brun:\s*\|/, "run:")
  .replace(/\s+/g, " ")
  .trim();

export const parseJobSteps = (job) => {
  const marker = "\n    steps:\n";
  const at = job.indexOf(marker);
  if (at < 0) return null;
  const body = job.slice(at + marker.length);
  const blocks = body.split(/\n(?=      - )/).map((b) => b.replace(/^\n/, "")).filter((b) => b.trim().startsWith("- "));
  return blocks.map((block) => {
    const uses = (block.match(/^\s+(?:-\s+)?uses:/gm) ?? []).length;
    const runs = (block.match(/^\s+(?:-\s+)?run:/gm) ?? []).length;
    if (uses + runs !== 1) return `invalid:${stepSignature(block).slice(0, 80)}`;
    return stepSignature(block);
  });
};

// Trust must never be bootstrapped inside the ceremony. These needles name
// the hosted discovery endpoint and every production trust input.
export const TRUST_BOOTSTRAP_PATTERNS = [
  /\/pubkey\b/i,
  /raven-hosted-verifier\.onrender\.com/i,
  /RAVEN_TRUSTED_KEYS/i,
];
// The workflow text itself must not even name production trust material.
const WORKFLOW_TRUST_PATTERNS = [
  ...TRUST_BOOTSTRAP_PATTERNS,
  /production-pins|trusted-keys|trustedKeys|signerPublicKey/i,
];
// Helpers reached from the workflow may not open the network at all.
const HELPER_NETWORK_PATTERNS = [
  /\bfetch\s*\(/,
  /["']node:https?["']|["']https?["']|["']undici["']/,
  /\bcurl\b|\bwget\b/,
];

const REGISTRY_OVERRIDE_PATTERNS = [
  /npm_config_registry/i,
  /NPM_CONFIG_REGISTRY/,
  /--registry\b/,
  /\.npmrc/,
  /npm\s+config\s+set/i,
];

export const validateWorkflowText = (workflow) => {
  const failures = [];
  const jobs = Object.fromEntries(JOB_ORDER.map((name, index) => [name, sliceJob(workflow, name, JOB_ORDER[index + 1])]));
  const { "source-gate": source, "package-artifact": pack, "tarball-gate": tarball, publish } = jobs;

  // Permissions: global read; gates read only; publish read + one OIDC grant.
  if (!/^permissions:\n  contents: read\n(?!  )/m.test(workflow)) failures.push("global permissions must be contents: read only");
  for (const [name, job] of [["source-gate", source], ["package-artifact", pack], ["tarball-gate", tarball]]) {
    if (!exactPermissions(job, ["contents: read"])) failures.push(`${name} permissions are not exactly contents: read`);
    if (/id-token|environment:|\$\{\{\s*secrets\./.test(job)) failures.push(`${name} gained publication authority or secrets`);
  }
  if (!exactPermissions(publish, ["contents: read", "      id-token: write"])) failures.push("publish permissions are not exactly contents: read and id-token: write");
  if (!/^    environment: npm-release$/m.test(publish)) failures.push("publish job lacks npm-release environment");
  if ((workflow.match(/id-token:\s*write/g) ?? []).length !== 1) failures.push("id-token: write must occur exactly once");
  if (/NODE_AUTH_TOKEN|NPM_TOKEN|_authToken|\$\{\{\s*secrets\./i.test(workflow)) failures.push("workflow references a token or secret");

  // Exact step allowlist per job (run: and uses: alike).
  for (const name of JOB_ORDER) {
    const actual = parseJobSteps(jobs[name]);
    const expected = EXPECTED_JOB_STEPS[name];
    if (!actual) { failures.push(`${name} has no steps block`); continue; }
    if (JSON.stringify(actual) !== JSON.stringify(expected)) {
      const extra = actual.filter((s) => !expected.includes(s));
      const missing = expected.filter((s) => !actual.includes(s));
      failures.push(`${name} steps differ from policy allowlist (extra: ${JSON.stringify(extra)}; missing: ${JSON.stringify(missing)}; count ${actual.length}/${expected.length})`);
    }
  }
  const checkouts = (workflow.match(/uses:\s*actions\/checkout@/g) ?? []).length;
  if (checkouts !== JOB_ORDER.length) failures.push(`expected exactly ${JOB_ORDER.length} checkouts, saw ${checkouts}`);
  if ((workflow.match(/persist-credentials:\s*false/g) ?? []).length !== JOB_ORDER.length) failures.push("every checkout must disable credential persistence");
  if (/persist-credentials:\s*true/.test(workflow)) failures.push("a checkout persists credentials");

  // Pack-once: exactly one direct pack, in package-artifact, and no
  // indirection anywhere (the allowlist already pins the text; keep the
  // independent invariants so a policy edit cannot silently relax them).
  if ((workflow.match(/^\s+npm pack\b/gm) ?? []).length !== 1) failures.push("workflow must contain exactly one direct npm pack");
  if (!/^\s+npm pack --json --pack-destination "\$RUNNER_TEMP\/release-package"/m.test(pack)) failures.push("authorized pack is not in package-artifact");
  if (/\bnpm pack\b/.test(source) || /\bnpm pack\b/.test(tarball) || /\bnpm pack\b/.test(publish)) failures.push("pack operation exists outside package-artifact");
  if (/^\s+(?:bash|sh)\s+(?:\.\/)?ops\//m.test(workflow) || /^\s+(?:\.\/)?ops\/[A-Za-z0-9._/-]+\.sh\b/m.test(workflow)) failures.push("workflow may not hide package creation behind a shell helper");
  if (/^\s+(?:npx|npm\s+exec)\b[^\n]*\bpack\b/gim.test(workflow)) failures.push("workflow contains indirect npm pack");
  if (/npm-cli\.js|libnpmpack|pacote/i.test(workflow)) failures.push("workflow invokes npm internals directly");
  if (/^\s+tar\s+[^\n]*(?:-[A-Za-z]*c[A-Za-z]*|--create)\b/gim.test(workflow)) failures.push("workflow reconstructs a tarball");
  if ((publish.match(/node ops\/publish-exact-release\.mjs/g) ?? []).length !== 1) failures.push("publish job must invoke one guarded publisher");
  if (/\bnpm\s+publish\b/.test(workflow)) failures.push("raw npm publish must not appear in workflow YAML");
  for (const helper of workflow.matchAll(/node\s+((?!ops\/)[A-Za-z0-9._/-]+\.(?:mjs|js|cjs))/g)) failures.push(`workflow invokes a helper outside ops/: ${helper[1]}`);
  for (const job of [source, pack, tarball, publish]) {
    if (!/node ops\/verify-release-ref\.mjs/.test(job)) failures.push("every job must resolve release ref/SHA/tree");
    if (!/node ops\/npm-version-gate\.mjs "\$\{RAVEN_PINNED_NPM_VERSION\}"/.test(job)) failures.push("every job must assert pinned npm");
  }

  // Action identity: every external action pinned to its approved SHA.
  for (const match of workflow.matchAll(/uses:\s*([^\s#]+)/g)) {
    const [, ref] = match;
    const at = ref.lastIndexOf("@");
    const action = at > 0 ? ref.slice(0, at) : ref;
    const sha = at > 0 ? ref.slice(at + 1) : "";
    if (!Object.hasOwn(APPROVED_ACTIONS, action)) failures.push(`action is not on the approved list: ${ref}`);
    else if (sha !== APPROVED_ACTIONS[action]) failures.push(`${action} is not pinned to its approved commit SHA (${sha || "<none>"})`);
  }

  // Trigger and inputs.
  const onBlock = workflow.slice(workflow.indexOf("\non:"), workflow.indexOf("\npermissions:"));
  if (!/workflow_dispatch:/.test(onBlock) || /\bpush:|pull_request:|schedule:|workflow_call:|repository_dispatch:/.test(onBlock)) {
    failures.push("publication workflow trigger is broader than manual dispatch");
  }
  for (const input of ["release_ref", "release_sha", "release_tree", "confirm_version"]) {
    if (!new RegExp(`\\n\\s{6}${input}:`).test(onBlock)) failures.push(`missing dispatch input ${input}`);
  }

  // Toolchain governance.
  if (!new RegExp(`^  RAVEN_PINNED_NPM_VERSION: "${PINNED_NPM_VERSION.replace(/\./g, "\\.")}"$`, "m").test(workflow)) failures.push("pinned npm env does not match policy");
  for (const [name, job] of [["source-gate", source], ["tarball-gate", tarball]]) {
    if (!job.includes(`node-version: ${GOVERNED_NODE_MATRIX}`)) failures.push(`${name} does not run the governed Node matrix`);
  }
  for (const [name, job] of [["package-artifact", pack], ["publish", publish]]) {
    if (!job.includes(`node-version: "${GOVERNED_PUBLISH_NODE}"`)) failures.push(`${name} does not pin the governed publish Node`);
  }

  // Registry endpoint: exactly one registry-url, in publish, equal to policy;
  // no override channel anywhere.
  const registryLines = [...workflow.matchAll(/^\s*registry-url:\s*(.+)$/gm)].map((m) => m[1].trim());
  if (registryLines.length !== 1) failures.push(`expected exactly one registry-url, saw ${registryLines.length}`);
  if (!publish.includes(`registry-url: "${PUBLICATION_REGISTRY}"`)) failures.push("publish setup-node does not name the pinned registry");
  for (const pattern of REGISTRY_OVERRIDE_PATTERNS) {
    if (pattern.test(workflow)) failures.push(`workflow contains a registry override channel (${pattern})`);
  }

  // Trust bootstrap: the ceremony never touches /pubkey or trust inputs.
  for (const pattern of WORKFLOW_TRUST_PATTERNS) {
    if (pattern.test(workflow)) failures.push(`workflow bootstraps trust dynamically (${pattern})`);
  }
  return failures;
};

const PACK_CREATION_PATTERNS = [
  // "npm pack" (or npx/npm exec ... pack) inside a string handed to an executor
  /(?:exec(?:Sync)?|spawn(?:Sync)?|execFile(?:Sync)?|run)\s*\(\s*["'`][^"'`\n]*\b(?:npm|npx)\b[^"'`\n]*\bpack\b/i,
  /["']npm(?:\.cmd)?["'][\s\S]{0,160}["']pack["']/i,
  /libnpmpack|pacote\.tarball|npm-cli\.js/i,
  /\b(?:spawn(?:Sync)?|execFile(?:Sync)?|exec(?:Sync)?|run)\(\s*["']tar["']\s*,\s*\[\s*["']-[A-Za-z]*c[A-Za-z]*["']/i,
  /\b(?:spawn(?:Sync)?|execFile(?:Sync)?|exec(?:Sync)?|run)\(\s*["'](?:bash|sh|zsh)["']/i,
  /\bexec(?:Sync)?\(\s*(?!["'](?:git|npm)\s)[^)]*\)/i,
  /\b(?:bash|sh)\s+(?:\.\/)?ops\//i,
];

export const scanInvokedPublicationHelpers = ({ root, workflow }) => {
  const failures = [];
  const queue = [...workflow.matchAll(/node\s+((?:[A-Za-z0-9._-]+\/)*[A-Za-z0-9._-]+\.(?:mjs|js|cjs))/g)].map((match) => match[1]);
  const visited = new Set();
  while (queue.length) {
    const helper = queue.shift();
    if (visited.has(helper)) continue;
    visited.add(helper);
    if (!/^ops\/[A-Za-z0-9._-]+\.mjs$/.test(helper)) {
      failures.push(`publication helper escapes ops/: ${helper}`);
      continue;
    }
    let body;
    try { body = readFileSync(path.join(root, helper), "utf8"); }
    catch { failures.push(`publication helper missing: ${helper}`); continue; }
    for (const pattern of PACK_CREATION_PATTERNS) {
      if (pattern.test(body)) failures.push(`${helper} can create or regenerate package bytes (${pattern})`);
    }
    for (const pattern of [...TRUST_BOOTSTRAP_PATTERNS, ...HELPER_NETWORK_PATTERNS]) {
      if (pattern.test(body)) failures.push(`${helper} bootstraps trust or opens the network (${pattern})`);
    }
    for (const match of body.matchAll(/from\s+["']\.\/([A-Za-z0-9._-]+\.mjs)["']/g)) {
      queue.push(`ops/${match[1]}`);
    }
  }
  return failures;
};
