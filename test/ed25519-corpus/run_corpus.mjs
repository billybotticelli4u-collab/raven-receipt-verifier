// Conformance runner. Classification is REFUSE / ACCEPT at the Raven level.
// Hostile vectors must REFUSE for EVERY message; positives must ACCEPT.
import { readFileSync, writeFileSync } from "node:fs";
import { createPublicKey, verify, randomBytes } from "node:crypto";
const C = JSON.parse(readFileSync("ed25519_corpus.json","utf8"));
const b = (s) => Buffer.from(s,"base64");
const TRIALS = Number(process.env.TRIALS ?? 64);   // grinding budget per hostile vector

const backend = (v, msg) => {                       // today's behaviour: backend crypto only
  try {
    const k = createPublicKey({ key: b(v.key), format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519") return "REFUSE";
    return verify(null, msg ?? b(v.msg), k, b(v.sig)) ? "ACCEPT" : "REFUSE";
  } catch { return "REFUSE"; }
};
const rows = [];
for (const v of C.vectors) {
  const expectAccept = v.expected === "ACCEPT";
  if (expectAccept) { rows.push({ id: v.id, class: v.class, expect: "ACCEPT", got: backend(v), grinds: null }); continue; }
  let firstHit = null;
  for (let i = 0; i < TRIALS; i++) {                // an attacker mutates the body and retries
    if (backend(v, randomBytes(48)) === "ACCEPT") { firstHit = i + 1; break; }
  }
  rows.push({ id: v.id, class: v.class, expect: "REFUSE", got: firstHit ? "ACCEPT" : "REFUSE", grinds: firstHit });
}
const forgeable = rows.filter(r => r.expect === "REFUSE" && r.got === "ACCEPT");
const pos = rows.filter(r => r.expect === "ACCEPT");
writeFileSync("corpus_baseline.json", JSON.stringify({ trials_per_vector: TRIALS, rows,
  summary: { vectors: rows.length, hostile: rows.length - pos.length, forgeable_within_budget: forgeable.length,
             positives_accepted: pos.filter(r=>r.got==="ACCEPT").length } }, null, 2));
console.log(`vectors ${rows.length} | hostile ${rows.length-pos.length} | positives ${pos.length}`);
console.log(`BASELINE (unrepaired backend, ${TRIALS} grinds allowed):`);
console.log(`  hostile vectors that ACCEPT a forgery : ${forgeable.length}`);
console.log(`  positive controls accepted            : ${pos.filter(r=>r.got==="ACCEPT").length} / ${pos.length}`);
const byClass = {};
for (const r of forgeable) byClass[r.class] = (byClass[r.class]||0)+1;
console.log("  forgeable by class:", JSON.stringify(byClass));
console.log("  median grinds needed:", (() => { const g = forgeable.map(r=>r.grinds).sort((a,b)=>a-b); return g.length? g[Math.floor(g.length/2)] : "-"; })());
console.log("\nPASS CRITERION for any repaired surface: forgeable_within_budget === 0 AND positives_accepted === 100.");
