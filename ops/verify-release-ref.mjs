// Verifies that the checked-out source is the exact owner-authorized release
// ref/SHA/tree. The workflow uses this immediately after checkout and again in
// the protected publish job; a wrong SHA or tree fails before any publish step.
import { spawnSync } from "node:child_process";

const env = process.env;
const expectedSha = env.RAVEN_RELEASE_SHA;
const expectedTree = env.RAVEN_RELEASE_TREE;
const expectedRef = env.RAVEN_RELEASE_REF;

const failures = [];

const git = (...args) => {
  const result = spawnSync("git", args, { encoding: "utf8" });
  if (result.status !== 0) {
    process.stdout.write(result.stdout ?? "");
    process.stderr.write(result.stderr ?? "");
    throw new Error(`git ${args.join(" ")} exited ${result.status}`);
  }
  return result.stdout.trim();
};

if (!/^[0-9a-f]{40}$/.test(expectedSha ?? "")) {
  failures.push(`release SHA input is not a full 40-hex commit: ${expectedSha ?? "<missing>"}`);
}

if (!/^[0-9a-f]{40}$/.test(expectedTree ?? "")) {
  failures.push(`release tree input is not a full 40-hex tree: ${expectedTree ?? "<missing>"}`);
}

if (!/^refs\/(heads|tags)\/[A-Za-z0-9._\/-]+$/.test(expectedRef ?? "")) {
  failures.push(`release ref input must be a full refs/heads/* or refs/tags/* ref: ${expectedRef ?? "<missing>"}`);
}

let actualSha;
let actualTree;
try {
  actualSha = git("rev-parse", "HEAD");
  actualTree = git("rev-parse", "HEAD^{tree}");
} catch (error) {
  failures.push(error.message);
}

if (actualSha && expectedSha && actualSha !== expectedSha) {
  failures.push(`HEAD ${actualSha} != authorized release SHA ${expectedSha}`);
}

if (actualTree && expectedTree && actualTree !== expectedTree) {
  failures.push(`HEAD tree ${actualTree} != authorized release tree ${expectedTree}`);
}

if (env.GITHUB_SHA && actualSha && env.GITHUB_SHA !== actualSha) {
  failures.push(`GITHUB_SHA ${env.GITHUB_SHA} != checked-out HEAD ${actualSha}`);
}

if (env.GITHUB_REF && expectedRef && env.GITHUB_REF !== expectedRef) {
  failures.push(`GITHUB_REF ${env.GITHUB_REF} != authorized release ref ${expectedRef}`);
}

if (failures.length) {
  for (const failure of failures) {
    console.error(`REFUSED release source: ${failure}`);
  }
  process.exit(1);
}

console.log(`release source verified: ${expectedRef} ${actualSha} ${actualTree}`);
