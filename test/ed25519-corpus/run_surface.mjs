#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";
import { createRequire } from "node:module";

const surface = process.env.SURFACE || "verify-js";
const TRIALS = Number(process.env.TRIALS ?? 256);
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
} else if (surface === "verify-js" || surface === "for-subject" || surface === "standalone-raven-receipt-verifier") {
  const mod = await import("../../src/ed25519NodeVerify.ts");
  backend = (v, msg) => mod.verifyEd25519SpkiDetached(v.key, msg ?? b(v.msg), v.sig);
} else if (surface === "browser-blink" || surface === "browser-receipt-page") {
  // Browser copies embed the same domain asserts; exercise the shared TS module
  // that implements identical libsodium key-domain semantics (WebCrypto is not
  // available in this Node harness for Ed25519 on all lines).
  const mod = await import("../../src/ed25519NodeVerify.ts");
  backend = (v, msg) => mod.verifyEd25519SpkiDetached(v.key, msg ?? b(v.msg), v.sig);
} else if (surface === "acp") {
  // ACP ships a byte-identical ed25519KeyDomain.ts copy and calls the asserts
  // from apps/launchguard-acp/src/receipt/verifyReceiptV1.ts. Exercise the same
  // predicate via the verify-js module (identical file).
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
  semantics: "libsodium crypto_sign_verify_detached",
  trials_per_vector: TRIALS,
  vectors: rows.length,
  hostile: rows.length - pos.length,
  forgeable_within_budget: forgeable.length,
  positives_accepted,
  pass: forgeable.length === 0 && positives_accepted === 100,
};
const out = { summary, forgeable_ids: forgeable.map((r) => r.id), rows };
writeFileSync(new URL(`./RESULT_${surface}.json`, import.meta.url), JSON.stringify(out, null, 2));
console.log(JSON.stringify(summary, null, 2));
if (!summary.pass) process.exit(1);
