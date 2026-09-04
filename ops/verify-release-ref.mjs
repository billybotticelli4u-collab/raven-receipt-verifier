import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import { PUBLICATION_REF } from "./release-policy.mjs";

const git = (args, options = {}) => {
  const result = spawnSync("git", args, { encoding: "utf8", ...options });
  if (result.status !== 0) {
    throw new Error(`git ${args.join(" ")} exited ${result.status}\n${result.stderr || result.stdout}`.trim());
  }
  return result.stdout.trim();
};

const isClean = (cwd) => {
  const unstaged = spawnSync("git", ["diff", "--quiet"], { cwd }).status === 0;
  const staged = spawnSync("git", ["diff", "--cached", "--quiet"], { cwd }).status === 0;
  return unstaged && staged;
};

export const verifyReleaseRef = ({
  releaseRef,
  releaseSha,
  releaseTree,
  githubRef,
  githubSha,
  remote = "origin",
  authorizedRef = PUBLICATION_REF,
  cwd = process.cwd(),
}) => {
  const failures = [];
  if (!/^[0-9a-f]{40}$/.test(releaseSha ?? "")) failures.push("release SHA must be full 40-hex");
  if (!/^[0-9a-f]{40}$/.test(releaseTree ?? "")) failures.push("release tree must be full 40-hex");
  if (!/^refs\/(heads|tags)\/[A-Za-z0-9._/-]+$/.test(releaseRef ?? "")) {
    failures.push("release ref must be a full branch or tag ref");
  }
  if (releaseRef !== authorizedRef) failures.push(`release ref ${releaseRef} is not authorized ${authorizedRef}`);
  if (githubRef !== releaseRef) failures.push(`GITHUB_REF ${githubRef} != release ref ${releaseRef}`);
  if (githubSha !== releaseSha) failures.push(`GITHUB_SHA ${githubSha} != release SHA ${releaseSha}`);
  if (!isClean(cwd)) failures.push("tracked worktree or index is not clean");
  if (failures.length) throw new Error(failures.join("\n"));

  const head = git(["rev-parse", "HEAD"], { cwd });
  const tree = git(["rev-parse", "HEAD^{tree}"], { cwd });
  if (head !== releaseSha) failures.push(`HEAD ${head} != release SHA ${releaseSha}`);
  if (tree !== releaseTree) failures.push(`HEAD tree ${tree} != release tree ${releaseTree}`);

  // Fetch the exact named ref into an isolated local ref on every invocation.
  // Peeling ^{commit} handles branches, lightweight tags, and annotated tags.
  const fetchedRef = "refs/raven-release/authorized-source";
  spawnSync("git", ["update-ref", "-d", fetchedRef], { cwd, encoding: "utf8" });
  try {
    git(["fetch", "--no-tags", "--force", remote, `${releaseRef}:${fetchedRef}`], { cwd });
    const resolvedCommit = git(["rev-parse", `${fetchedRef}^{commit}`], { cwd });
    const resolvedTree = git(["rev-parse", `${fetchedRef}^{commit}^{tree}`], { cwd });
    if (resolvedCommit !== releaseSha) {
      failures.push(`${releaseRef} resolves to ${resolvedCommit}, not release SHA ${releaseSha}`);
    }
    if (resolvedTree !== releaseTree) {
      failures.push(`${releaseRef} tree ${resolvedTree} != release tree ${releaseTree}`);
    }
  } catch (error) {
    failures.push(error.message);
  } finally {
    spawnSync("git", ["update-ref", "-d", fetchedRef], { cwd, encoding: "utf8" });
  }
  if (failures.length) throw new Error(failures.join("\n"));
  return { head, tree, releaseRef };
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const result = verifyReleaseRef({
      releaseRef: process.env.RAVEN_RELEASE_REF,
      releaseSha: process.env.RAVEN_RELEASE_SHA,
      releaseTree: process.env.RAVEN_RELEASE_TREE,
      githubRef: process.env.GITHUB_REF,
      githubSha: process.env.GITHUB_SHA,
      remote: process.env.RAVEN_RELEASE_REMOTE ?? "origin",
    });
    console.log(`release source resolved and verified: ${result.releaseRef} ${result.head} ${result.tree}`);
  } catch (error) {
    console.error(`REFUSED release source: ${error.message}`);
    process.exit(1);
  }
}
