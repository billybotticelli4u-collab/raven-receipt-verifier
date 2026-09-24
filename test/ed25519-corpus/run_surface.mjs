#!/usr/bin/env node
import { readFileSync, writeFileSync, realpathSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import { resolve, dirname, basename, relative, isAbsolute, sep } from "node:path";

const surface = process.env.SURFACE || "shared-node-predicate";
const applicationSurfaces = new Set(['verify-js', 'for-subject', 'standalone-raven-receipt-verifier', 'browser-blink', 'browser-receipt-page', 'acp']);
if (applicationSurfaces.has(surface)) {
  console.log(JSON.stringify({ status: 'NOT_EXECUTED', requested_surface: surface, executed_implementation: null, pass: false, reason: 'This harness executes detached predicates, not application entry points. Use run_browser_applications.mjs for browsers. ACP verifyReceiptV1 has no production caller in the inspected source tree.' }));
  process.exit(2);
}
const implementations = {
  'shared-node-predicate': 'packages/verify-js/src/ed25519NodeVerify.ts#verifyEd25519SpkiDetached',
  'unrepaired-backend': 'node:crypto#verify (without Raven key-domain predicate)',
  'python': 'reference-verifiers/python/raven_verify.py#ed25519_verify + key/signature domain guards',
};
if (!Object.hasOwn(implementations, surface)) throw new Error('unknown SURFACE=' + surface);
if (!process.env.OUT) throw new Error('OUT must name a new evidence file outside the repository');
const output = resolve(realpathSync(dirname(resolve(process.env.OUT))), basename(process.env.OUT));
const repo = realpathSync(fileURLToPath(new URL('../../../../', import.meta.url)));
const outputRelative = relative(repo, output);
if (!outputRelative.startsWith('..' + sep) && !isAbsolute(outputRelative)) throw new Error('Evidence output must be outside the repository');
const TRIALS = Number(process.env.TRIALS ?? 256);
if (!Number.isSafeInteger(TRIALS) || TRIALS < 1) throw new Error('TRIALS must be a positive integer');
const C = JSON.parse(readFileSync(new URL("./ed25519_corpus.json", import.meta.url), "utf8"));
const b = (s) => Buffer.from(s, "base64");

let backend;
if (surface === "unrepaired-backend") {
  const { createPublicKey, verify } = await import("node:crypto");
  backend = (v, msg) => {
    try {
      const k = createPublicKey({ key: b(v.key), format: "der", type: "spki" });
      if (k.asymmetricKeyType !== "ed25519") return "REFUSE";
      return verify(null, msg ?? b(v.msg), k, b(v.sig)) ? "ACCEPT" : "REFUSE";
    } catch { return "REFUSE"; }
  };
} else if (surface === "shared-node-predicate") {
  const mod = await import("../../src/ed25519NodeVerify.ts");
  backend = (v, msg) => mod.verifyEd25519SpkiDetached(v.key, msg ?? b(v.msg), v.sig);
} else if (surface === "python") {
  const { spawnSync } = await import("node:child_process");
  const { fileURLToPath } = await import("node:url");
  const pyPath = fileURLToPath(new URL("../../../../reference-verifiers/python/", import.meta.url));
  backend = (v, msg) => {
    const payload = JSON.stringify({ key: v.key, sig: v.sig, msg_b64: (msg ?? b(v.msg)).toString("base64") });
    const code = [
      "import json,sys,base64",
      "sys.path.insert(0, " + JSON.stringify(pyPath) + ")",
      "from raven_verify import raw_key_from_spki_base64, ed25519_verify, _decode_canonical_base64, assert_ed25519_signature_raw",
      "v=json.loads(sys.stdin.read())",
      "msg=base64.b64decode(v['msg_b64'])",
      "try:",
      "  raw=raw_key_from_spki_base64(v['key'])",
      "  sig=_decode_canonical_base64(v['sig'])",
      "  assert_ed25519_signature_raw(sig)",
      "  ok=ed25519_verify(raw, msg, sig)",
      "  print('ACCEPT' if ok else 'REFUSE')",
      "except Exception:",
      "  print('REFUSE')",
    ].join("\n");
    const r = spawnSync("python3", ["-c", code], { input: payload, encoding: "utf8" });
    if (r.error || r.status !== 0) throw new Error('PYTHON_NOT_EXECUTED: ' + (r.error?.message ?? r.stderr));
    return (r.stdout || "").trim() === "ACCEPT" ? "ACCEPT" : "REFUSE";
  };
} else {
  throw new Error("unknown SURFACE="+surface);
}

const rows = [];
for (const v of C.vectors) {
  const expectAccept = v.expected === "ACCEPT";
  if (expectAccept) {
    rows.push({ id: v.id, class: v.class, expect: "ACCEPT", got: backend(v), grinds: null });
    continue;
  }
  let firstHit = null;
  for (let i = 0; i < TRIALS; i++) {
    if (backend(v, randomBytes(48)) === "ACCEPT") { firstHit = i + 1; break; }
  }
  rows.push({
    id: v.id,
    class: v.class,
    expect: "REFUSE",
    got: firstHit === null ? "REFUSE" : "ACCEPT",
    grinds: firstHit,
  });
}
const forgeable = rows.filter((r) => r.expect === "REFUSE" && r.got === "ACCEPT");
const pos = rows.filter((r) => r.expect === "ACCEPT");
const positives_accepted = pos.filter((r) => r.got === "ACCEPT").length;
const summary = {
  surface,
  status: 'EXECUTED',
  measurement: 'detached predicate; not application conformance',
  executed_implementation: implementations[surface],
  semantics: "Raven detached-predicate corpus measurement; not application or libsodium equivalence certification",
  trials_per_vector: TRIALS,
  vectors: rows.length,
  hostile: rows.length - pos.length,
  forgeable_within_budget: forgeable.length,
  positives_accepted,
  pass: rows.length === 169 && pos.length === 100 && forgeable.length === 0 && positives_accepted === 100,
};
const out = { summary, forgeable_ids: forgeable.map((r) => r.id), rows };
writeFileSync(output, JSON.stringify(out, null, 2), { flag: 'wx' });
console.log(JSON.stringify(summary, null, 2));
if (!summary.pass) process.exit(1);
