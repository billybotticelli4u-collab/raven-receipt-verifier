#!/usr/bin/env node
/**
 * Pack the package, extract the tarball, grind Ed25519 corpus against
 * package/dist/ed25519NodeVerify.js. Expect 0 forgeable / 100 positives.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { randomBytes } from "node:crypto";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = join(__dirname, "..");
const TRIALS = Number(process.env.TRIALS || 256);
const corpusPath = join(root, "test/ed25519-corpus/ed25519_corpus.json");

const scratch = mkdtempSync(join(tmpdir(), "rrv-packed-ed25519-"));
try {
  const pack = spawnSync("npm", ["pack", "--pack-destination", scratch], {
    cwd: root,
    encoding: "utf8",
  });
  if (pack.status !== 0) {
    console.error(pack.stdout, pack.stderr);
    process.exit(pack.status || 1);
  }
  const tgz = join(scratch, "raven-receipt-verifier-0.1.0.tgz");
  const untar = spawnSync("tar", ["-xzf", tgz, "-C", scratch], {
    encoding: "utf8",
  });
  if (untar.status !== 0) {
    console.error(untar.stderr);
    process.exit(1);
  }
  const modPath = join(scratch, "package/dist/ed25519NodeVerify.js");
  const packedMod = await import(pathToFileURL(modPath).href);
  const C = JSON.parse(readFileSync(corpusPath, "utf8"));
  const b = (s) => Buffer.from(s, "base64");
  const backend = (v, msg) =>
    packedMod.verifyEd25519SpkiDetached(v.key, msg ?? b(v.msg), v.sig);

  let forgeable = 0,
    positives = 0,
    hostile = 0;
  for (const v of C.vectors) {
    if (v.expected === "ACCEPT") {
      if (backend(v) === "ACCEPT") positives++;
      else {
        console.error("positive_rejected", v.id);
        process.exit(2);
      }
      continue;
    }
    hostile++;
    let hit = false;
    for (let i = 0; i < TRIALS; i++) {
      if (backend(v, randomBytes(48)) === "ACCEPT") {
        hit = true;
        break;
      }
    }
    if (hit) forgeable++;
  }
  const out = {
    surface: "packed-ed25519NodeVerify.js",
    semantics: packedMod.ED25519_KEY_DOMAIN_SEMANTICS,
    trials_per_vector: TRIALS,
    vectors: C.vectors.length,
    hostile,
    forgeable_within_budget: forgeable,
    positives_accepted: positives,
    pass: forgeable === 0 && positives === 100,
  };
  console.log(JSON.stringify(out, null, 2));
  process.exit(out.pass ? 0 : 1);
} finally {
  rmSync(scratch, { recursive: true, force: true });
}
