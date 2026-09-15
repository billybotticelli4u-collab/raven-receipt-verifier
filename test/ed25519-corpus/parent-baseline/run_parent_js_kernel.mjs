import { readFileSync, writeFileSync } from "node:fs";
import { createPublicKey, verify, randomBytes } from "node:crypto";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
const C = JSON.parse(readFileSync(process.env.CORPUS,"utf8"));
const TRIALS = Number(process.env.TRIALS ?? 256);
const b = (s) => Buffer.from(s,"base64");
// Parent behavior: canonical base64 + exact SPKI prefix, NO small-order check
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const decodeCanonicalBase64 = (value) => {
  if (!CANONICAL_BASE64.test(value)) throw new Error("noncanonical base64");
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) throw new Error("noncanonical base64");
  return decoded;
};
const decodeCanonicalEd25519Spki = (value) => {
  const decoded = decodeCanonicalBase64(value);
  if (decoded.length !== ED25519_SPKI_PREFIX.length + 32 || !decoded.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)) {
    throw new Error("not a canonical Ed25519 SPKI key");
  }
  return decoded;
};
const backend = (v, msg) => {
  try {
    const der = decodeCanonicalEd25519Spki(v.key);
    const sig = decodeCanonicalBase64(v.sig);
    const k = createPublicKey({ key: der, format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519") return "REFUSE";
    return verify(null, msg ?? b(v.msg), k, sig) ? "ACCEPT" : "REFUSE";
  } catch { return "REFUSE"; }
};
const rows=[];
for (const v of C.vectors) {
  if (v.expected==="ACCEPT") { rows.push({id:v.id,class:v.class,expect:"ACCEPT",got:backend(v),grinds:null}); continue; }
  let hit=null; for(let i=0;i<TRIALS;i++){ if(backend(v,randomBytes(48))==="ACCEPT"){hit=i+1;break;} }
  rows.push({id:v.id,class:v.class,expect:"REFUSE",got:hit==null?"REFUSE":"ACCEPT",grinds:hit});
}
const forgeable=rows.filter(r=>r.expect==="REFUSE"&&r.got==="ACCEPT");
const pos=rows.filter(r=>r.expect==="ACCEPT");
const by={}; for(const r of forgeable) by[r.class]=(by[r.class]||0)+1;
const summary={surface:"parent-js-kernel-decode+openssl",parent:"18b1a13c601cc362404dc6306fd8f4d1cc3e046e",trials:TRIALS,forgeable_within_budget:forgeable.length,positives_accepted:pos.filter(r=>r.got==="ACCEPT").length,forgeable_by_class:by};
writeFileSync(process.env.OUT+"/PARENT_JS_KERNEL.json", JSON.stringify({summary,forgeable_ids:forgeable.map(r=>r.id),rows},null,2));
console.log(JSON.stringify(summary,null,2));
