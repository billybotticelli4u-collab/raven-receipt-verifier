import { readFileSync } from "node:fs";
import path from "node:path";

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

export const validateWorkflowText = (workflow) => {
  const failures = [];
  const source = sliceJob(workflow, "source-gate", "package-artifact");
  const pack = sliceJob(workflow, "package-artifact", "tarball-gate");
  const tarball = sliceJob(workflow, "tarball-gate", "publish");
  const publish = sliceJob(workflow, "publish");
  if (!/^permissions:\n  contents: read\n/m.test(workflow)) failures.push("global permissions must be contents: read only");
  for (const [name, job] of [["source-gate", source], ["package-artifact", pack], ["tarball-gate", tarball]]) {
    if (!exactPermissions(job, ["contents: read"])) failures.push(`${name} permissions are not exactly contents: read`);
    if (/id-token|environment:|\$\{\{\s*secrets\./.test(job)) failures.push(`${name} gained publication authority or secrets`);
  }
  if (!exactPermissions(publish, ["contents: read", "      id-token: write"])) failures.push("publish permissions are not exactly contents: read and id-token: write");
  if (!/^    environment: npm-release$/m.test(publish)) failures.push("publish job lacks npm-release environment");
  if ((workflow.match(/id-token:\s*write/g) ?? []).length !== 1) failures.push("id-token: write must occur exactly once");
  if (/NODE_AUTH_TOKEN|NPM_TOKEN|_authToken|\$\{\{\s*secrets\./i.test(workflow)) failures.push("workflow references a token or secret");
  if ((workflow.match(/persist-credentials:\s*false/g) ?? []).length !== 4) failures.push("every checkout must disable credential persistence");
  if ((workflow.match(/^\s+npm pack\b/gm) ?? []).length !== 1) failures.push("workflow must contain exactly one direct npm pack");
  if (!/^\s+npm pack --json --pack-destination "\$RUNNER_TEMP\/release-package"/m.test(pack)) failures.push("authorized pack is not in package-artifact");
  if (/\bnpm pack\b/.test(source) || /\bnpm pack\b/.test(tarball) || /\bnpm pack\b/.test(publish)) failures.push("pack operation exists outside package-artifact");
  if ((publish.match(/node ops\/publish-exact-release\.mjs/g) ?? []).length !== 1) failures.push("publish job must invoke one guarded publisher");
  if (/\bnpm\s+publish\b/.test(workflow)) failures.push("raw npm publish must not appear in workflow YAML");
  if ((publish.match(/^\s+run:/gm) ?? []).length !== 4) failures.push("publish job contains an unexpected executable step");
  for (const job of [source, pack, tarball, publish]) {
    if (!/node ops\/verify-release-ref\.mjs/.test(job)) failures.push("every job must resolve release ref/SHA/tree");
    if (!/node ops\/npm-version-gate\.mjs "\$\{RAVEN_PINNED_NPM_VERSION\}"/.test(job)) failures.push("every job must assert pinned npm");
  }
  const uses = [...workflow.matchAll(/uses:\s*([^\s#]+)/g)].map((match) => match[1]);
  for (const action of uses) {
    if (!/@[0-9a-f]{40}$/.test(action)) failures.push(`action is not pinned to a full SHA: ${action}`);
  }
  const onBlock = workflow.slice(workflow.indexOf("\non:"), workflow.indexOf("\npermissions:"));
  if (!/workflow_dispatch:/.test(onBlock) || /\bpush:|pull_request:|schedule:|workflow_call:/.test(onBlock)) {
    failures.push("publication workflow trigger is broader than manual dispatch");
  }
  for (const input of ["release_ref", "release_sha", "release_tree", "confirm_version"]) {
    if (!new RegExp(`\\n\\s{6}${input}:`).test(onBlock)) failures.push(`missing dispatch input ${input}`);
  }
  return failures;
};

const PACK_CREATION_PATTERNS = [
  /\bnpm\s+(?:exec\s+[^\n]+\s+)?pack\b/i,
  /["']npm(?:\.cmd)?["'][\s\S]{0,160}["']pack["']/i,
  /libnpmpack|pacote\.tarball/i,
  /\b(?:spawn(?:Sync)?|execFile(?:Sync)?|run)\(\s*["']tar["']\s*,\s*\[\s*["']-[A-Za-z]*c[A-Za-z]*["']/i,
];

export const scanInvokedPublicationHelpers = ({ root, workflow }) => {
  const failures = [];
  const queue = [...workflow.matchAll(/node\s+(ops\/[A-Za-z0-9._-]+\.mjs)/g)].map((match) => match[1]);
  const visited = new Set();
  while (queue.length) {
    const helper = queue.shift();
    if (visited.has(helper)) continue;
    visited.add(helper);
    if (!/^ops\/[A-Za-z0-9._-]+\.mjs$/.test(helper)) {
      failures.push(`publication helper escapes ops/: ${helper}`);
      continue;
    }
    const body = readFileSync(path.join(root, helper), "utf8");
    for (const pattern of PACK_CREATION_PATTERNS) {
      if (pattern.test(body)) failures.push(`${helper} can create or regenerate package bytes (${pattern})`);
    }
    for (const match of body.matchAll(/from\s+["']\.\/([A-Za-z0-9._-]+\.mjs)["']/g)) {
      queue.push(`ops/${match[1]}`);
    }
  }
  return failures;
};
