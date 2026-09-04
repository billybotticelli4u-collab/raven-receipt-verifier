import { spawnSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";

import {
  UPSTREAM_ACCEPTED_COMMIT,
  UPSTREAM_ACCEPTED_TREE,
} from "./release-policy.mjs";
import { gitObjectHash, gitTreeHash } from "./verify-byte-correspondence.mjs";

const upstreamRoot = process.argv[2];
const output = process.argv[3] ?? "release/private-public-byte-correspondence.json";
if (!upstreamRoot) throw new Error("usage: node ops/create-byte-correspondence.mjs <upstream-worktree> [output]");

const git = (cwd, args) => {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || `git ${args.join(" ")} failed`);
  return result.stdout.trim();
};

if (git(upstreamRoot, ["rev-parse", "HEAD"]) !== UPSTREAM_ACCEPTED_COMMIT) {
  throw new Error("upstream worktree is not the accepted commit");
}
if (git(upstreamRoot, ["rev-parse", "HEAD^{tree}"]) !== UPSTREAM_ACCEPTED_TREE) {
  throw new Error("upstream worktree is not the accepted tree");
}

const treeLines = git(upstreamRoot, ["ls-tree", "-r", UPSTREAM_ACCEPTED_COMMIT, "packages/verify-js"])
  .split("\n")
  .filter(Boolean);
const entries = treeLines.map((line) => {
  const match = /^(\d+) blob ([0-9a-f]{40})\t(.+)$/.exec(line);
  if (!match) throw new Error(`unexpected ls-tree record: ${line}`);
  const [, mode, privateBlob, privatePath] = match;
  const publicPath = privatePath;
  const publicBytes = readFileSync(publicPath);
  const publicBlob = gitObjectHash("blob", publicBytes);
  const metadataDelta = privatePath === "packages/verify-js/package.json";
  let normalizedPublicBlob;
  if (metadataDelta) {
    const manifest = JSON.parse(publicBytes.toString("utf8"));
    delete manifest.repository;
    normalizedPublicBlob = gitObjectHash("blob", Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`));
    if (normalizedPublicBlob !== privateBlob) throw new Error("package.json has more than the authorized repository delta");
  } else if (publicBlob !== privateBlob) {
    throw new Error(`${privatePath} differs from accepted source`);
  }
  return {
    privatePath,
    privateBlob,
    publicPath,
    publicBlob,
    mode,
    relationship: metadataDelta ? "AUTHORIZED_PUBLIC_METADATA_ONLY" : "IDENTICAL",
    ...(metadataDelta ? { normalizedPublicBlob } : {}),
  };
});

const privateTreeEntries = entries.map((entry) => ({
  path: entry.privatePath.replace(/^packages\/verify-js\//, ""),
  mode: entry.mode,
  hash: entry.privateBlob,
}));
const publicTreeEntries = entries.map((entry) => ({
  path: entry.publicPath.replace(/^packages\/verify-js\//, ""),
  mode: entry.mode,
  hash: entry.publicBlob,
}));
const privatePackageTree = gitTreeHash(privateTreeEntries);
const expectedPrivatePackageTree = git(upstreamRoot, ["rev-parse", `${UPSTREAM_ACCEPTED_COMMIT}:packages/verify-js`]);
if (privatePackageTree !== expectedPrivatePackageTree) throw new Error("manifest does not reconstruct accepted package tree");

const manifest = {
  schema: "raven-private-public-byte-correspondence/1",
  note: "Release evidence, not an independent trust root. Upstream commit/tree authorization remains an Owner decision.",
  hashAlgorithm: "git-blob-sha1",
  upstreamSource: {
    commit: UPSTREAM_ACCEPTED_COMMIT,
    tree: UPSTREAM_ACCEPTED_TREE,
    packageTree: privatePackageTree,
  },
  publicMirror: {
    packageTree: gitTreeHash(publicTreeEntries),
    authorizedDelta: "packages/verify-js/package.json repository metadata only",
  },
  entries,
};
writeFileSync(path.resolve(output), `${JSON.stringify(manifest, null, 2)}\n`, "utf8");
console.log(`wrote ${entries.length}-file correspondence manifest: ${path.resolve(output)}`);
