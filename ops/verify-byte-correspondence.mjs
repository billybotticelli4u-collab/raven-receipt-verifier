import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";

import {
  PUBLIC_REPOSITORY,
  UPSTREAM_ACCEPTED_COMMIT,
  UPSTREAM_ACCEPTED_TREE,
} from "./release-policy.mjs";

export const gitObjectHash = (type, bytes) => {
  const header = Buffer.from(`${type} ${bytes.length}\0`, "utf8");
  return createHash("sha1").update(header).update(bytes).digest("hex");
};

export const gitTreeHash = (entries) => {
  const root = { files: [], dirs: new Map() };
  for (const entry of entries) {
    const parts = entry.path.split("/");
    let node = root;
    for (const part of parts.slice(0, -1)) {
      if (!node.dirs.has(part)) node.dirs.set(part, { files: [], dirs: new Map() });
      node = node.dirs.get(part);
    }
    node.files.push({ name: parts.at(-1), mode: entry.mode, hash: entry.hash });
  }
  const hashNode = (node) => {
    const children = [
      ...node.files.map((file) => ({ ...file, sortName: file.name })),
      ...[...node.dirs].map(([name, child]) => ({
        name,
        mode: "40000",
        hash: hashNode(child),
        sortName: `${name}/`,
      })),
    ].sort((left, right) => Buffer.from(left.sortName).compare(Buffer.from(right.sortName)));
    const body = Buffer.concat(children.map(({ mode, name, hash }) => Buffer.concat([
      Buffer.from(`${mode} ${name}\0`, "utf8"),
      Buffer.from(hash, "hex"),
    ])));
    return gitObjectHash("tree", body);
  };
  return hashNode(root);
};

const normalizedMetadataBuffer = (bytes) => {
  const manifest = JSON.parse(bytes.toString("utf8"));
  if (JSON.stringify(manifest.repository) !== JSON.stringify({
    type: "git",
    url: PUBLIC_REPOSITORY,
    directory: "packages/verify-js",
  })) {
    throw new Error("public package.json repository metadata is not the authorized delta");
  }
  delete manifest.repository;
  return Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`, "utf8");
};

export const verifyCorrespondence = ({ root, manifest }) => {
  const failures = [];
  if (manifest.upstreamSource?.commit !== UPSTREAM_ACCEPTED_COMMIT) failures.push("wrong upstream commit");
  if (manifest.upstreamSource?.tree !== UPSTREAM_ACCEPTED_TREE) failures.push("wrong upstream tree");

  const publicTreeEntries = [];
  const privateTreeEntries = [];
  const manifestPaths = [];
  for (const entry of manifest.entries ?? []) {
    manifestPaths.push(entry.publicPath);
    const absolute = path.join(root, entry.publicPath);
    const publicBytes = readFileSync(absolute);
    const publicBlob = gitObjectHash("blob", publicBytes);
    if (publicBlob !== entry.publicBlob) failures.push(`${entry.publicPath}: public blob mismatch`);
    if (entry.relationship === "IDENTICAL") {
      if (publicBlob !== entry.privateBlob) failures.push(`${entry.publicPath}: executable/source bytes differ from accepted input`);
    } else if (entry.relationship === "AUTHORIZED_PUBLIC_METADATA_ONLY") {
      try {
        const normalizedBlob = gitObjectHash("blob", normalizedMetadataBuffer(publicBytes));
        if (normalizedBlob !== entry.privateBlob || normalizedBlob !== entry.normalizedPublicBlob) {
          failures.push(`${entry.publicPath}: metadata-normalized bytes differ from accepted input`);
        }
      } catch (error) {
        failures.push(`${entry.publicPath}: ${error.message}`);
      }
    } else {
      failures.push(`${entry.publicPath}: unauthorized relationship ${entry.relationship}`);
    }
    publicTreeEntries.push({ path: entry.publicPath.replace(/^packages\/verify-js\//, ""), mode: entry.mode, hash: publicBlob });
    privateTreeEntries.push({ path: entry.privatePath.replace(/^packages\/verify-js\//, ""), mode: entry.mode, hash: entry.privateBlob });
  }

  const lsFiles = spawnSync("git", ["ls-files", "packages/verify-js"], { cwd: root, encoding: "utf8" });
  if (lsFiles.status !== 0) failures.push("could not enumerate tracked public package files");
  else {
    const tracked = lsFiles.stdout.trim().split("\n").filter(Boolean).sort();
    if (JSON.stringify(tracked) !== JSON.stringify([...manifestPaths].sort())) {
      failures.push("tracked public package file set differs from correspondence manifest");
    }
  }

  const privateTree = gitTreeHash(privateTreeEntries);
  const publicTree = gitTreeHash(publicTreeEntries);
  if (privateTree !== manifest.upstreamSource?.packageTree) failures.push(`upstream package tree mismatch: ${privateTree}`);
  if (publicTree !== manifest.publicMirror?.packageTree) failures.push(`public package tree mismatch: ${publicTree}`);
  if (failures.length) throw new Error(failures.join("\n"));
  return { privateTree, publicTree, entries: manifest.entries.length };
};

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const root = process.cwd();
    const manifest = JSON.parse(readFileSync(path.join(root, "release/private-public-byte-correspondence.json"), "utf8"));
    const result = verifyCorrespondence({ root, manifest });
    console.log(`private/public byte correspondence verified: ${result.entries} files`);
    console.log(`accepted package tree: ${result.privateTree}`);
    console.log(`public package tree: ${result.publicTree}`);
  } catch (error) {
    console.error(`REFUSED byte correspondence: ${error.message}`);
    process.exit(1);
  }
}
