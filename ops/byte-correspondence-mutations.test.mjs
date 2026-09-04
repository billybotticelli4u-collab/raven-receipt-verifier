import assert from "node:assert/strict";
import { copyFileSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { verifyCorrespondence } from "./verify-byte-correspondence.mjs";

const ROOT = fileURLToPath(new URL("../", import.meta.url));
const MANIFEST = JSON.parse(readFileSync(path.join(ROOT, "release/private-public-byte-correspondence.json")));
const PUBLIC_BASE = "1b04356a275742752fb7afd8dfcc4269d462a778";

const git = (cwd, ...args) => {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  if (result.status !== 0) throw new Error(result.stderr || result.stdout);
  return result.stdout;
};

const mirrorFixture = () => {
  const scratch = mkdtempSync(path.join(tmpdir(), "raven-byte-correspondence-"));
  for (const entry of MANIFEST.entries) {
    const destination = path.join(scratch, entry.publicPath);
    mkdirSync(path.dirname(destination), { recursive: true });
    copyFileSync(path.join(ROOT, entry.publicPath), destination);
  }
  git(scratch, "init");
  git(scratch, "add", "packages/verify-js");
  return scratch;
};

test("positive control: every mirrored package blob reconstructs the accepted private tree", () => {
  const result = verifyCorrespondence({ root: ROOT, manifest: MANIFEST });
  assert.equal(result.entries, 86);
  assert.equal(result.privateTree, MANIFEST.upstreamSource.packageTree);
  assert.equal(result.publicTree, MANIFEST.publicMirror.packageTree);
});

test("M24 an unlisted public/private runtime blob mismatch turns RED", () => {
  const scratch = mirrorFixture();
  try {
    const target = path.join(scratch, "packages/verify-js/src/index.ts");
    writeFileSync(target, `${readFileSync(target, "utf8")}\nexport const unauthorized = true;\n`);
    assert.throws(() => verifyCorrespondence({ root: scratch, manifest: MANIFEST }), /blob mismatch|bytes differ|tree mismatch/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});

test("M25 stale bf91-derived trust implementation cannot substitute for accepted 610b bytes", () => {
  const acceptedPath = "packages/verify-js/src/verifyReceiptV1.ts";
  const accepted = readFileSync(path.join(ROOT, acceptedPath), "utf8");
  const stale = git(ROOT, "show", `${PUBLIC_BASE}:${acceptedPath}`);
  assert.match(accepted, /trust_key_type_unsupported/);
  assert.doesNotMatch(stale, /trust_key_type_unsupported/);

  const scratch = mirrorFixture();
  try {
    writeFileSync(path.join(scratch, acceptedPath), stale);
    assert.throws(() => verifyCorrespondence({ root: scratch, manifest: MANIFEST }), /public blob mismatch|bytes differ|tree mismatch/);
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
});
