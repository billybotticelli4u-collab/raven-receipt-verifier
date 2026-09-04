import assert from "node:assert/strict";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";

import { verifyReleaseRef } from "./verify-release-ref.mjs";

const runGit = (cwd, ...args) => {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return result.stdout.trim();
};

const identity = (cwd, commit = "HEAD") => ({
  commit: runGit(cwd, "rev-parse", `${commit}^{commit}`),
  tree: runGit(cwd, "rev-parse", `${commit}^{commit}^{tree}`),
});

const verify = (cwd, ref, expected) => verifyReleaseRef({
  releaseRef: ref,
  releaseSha: expected.commit,
  releaseTree: expected.tree,
  githubRef: ref,
  githubSha: expected.commit,
  remote: "origin",
  authorizedRef: ref,
  cwd,
});

test("M2-M6 exact ref resolution rejects SHA/tree/branch/tag substitution", () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-ref-mutations-"));
  const work = path.join(scratch, "work");
  const remote = path.join(scratch, "origin.git");
  try {
    runGit(scratch, "init", "work");
    runGit(work, "config", "user.email", "release-test@invalid.example");
    runGit(work, "config", "user.name", "Raven Release Test");
    writeFileSync(path.join(work, "identity.txt"), "A\n");
    runGit(work, "add", "identity.txt");
    runGit(work, "commit", "-m", "A");
    const a = identity(work);
    writeFileSync(path.join(work, "identity.txt"), "B\n");
    runGit(work, "add", "identity.txt");
    runGit(work, "commit", "-m", "B");
    const b = identity(work);
    runGit(scratch, "init", "--bare", "origin.git");
    runGit(work, "remote", "add", "origin", remote);
    runGit(work, "push", "origin", `HEAD:refs/heads/main`);

    assert.deepEqual(verify(work, "refs/heads/main", b), {
      head: b.commit,
      tree: b.tree,
      releaseRef: "refs/heads/main",
    });

    assert.throws(() => verifyReleaseRef({
      releaseRef: "refs/heads/main", releaseSha: a.commit, releaseTree: b.tree,
      githubRef: "refs/heads/main", githubSha: a.commit, remote: "origin",
      authorizedRef: "refs/heads/main", cwd: work,
    }), /HEAD|resolves/); // M2

    assert.throws(() => verifyReleaseRef({
      releaseRef: "refs/heads/main", releaseSha: b.commit, releaseTree: a.tree,
      githubRef: "refs/heads/main", githubSha: b.commit, remote: "origin",
      authorizedRef: "refs/heads/main", cwd: work,
    }), /tree/); // M3

    runGit(remote, "update-ref", "refs/heads/main", a.commit);
    assert.throws(() => verify(work, "refs/heads/main", b), /resolves/); // M4
    runGit(remote, "update-ref", "refs/heads/main", b.commit);

    runGit(work, "-c", "tag.gpgSign=false", "tag", "lightweight-wrong", a.commit);
    runGit(work, "push", "origin", "refs/tags/lightweight-wrong");
    assert.throws(() => verify(work, "refs/tags/lightweight-wrong", b), /resolves/); // M5

    runGit(work, "-c", "tag.gpgSign=false", "tag", "-a", "-m", "wrong target", "annotated-wrong", a.commit);
    runGit(work, "push", "origin", "refs/tags/annotated-wrong");
    assert.throws(() => verify(work, "refs/tags/annotated-wrong", b), /resolves/); // M6

    assert.throws(() => verifyReleaseRef({
      releaseRef: "refs/heads/not-main", releaseSha: b.commit, releaseTree: b.tree,
      githubRef: "refs/heads/not-main", githubSha: b.commit, remote: "origin",
      authorizedRef: "refs/heads/main", cwd: work,
    }), /not authorized/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
