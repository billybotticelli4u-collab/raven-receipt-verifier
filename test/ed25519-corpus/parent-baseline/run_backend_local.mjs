import { readFileSync, writeFileSync } from "node:fs";
import { createPublicKey, verify, randomBytes } from "node:crypto";
const C = JSON.parse(readFileSync(process.env.CORPUS,"utf8"));
const TRIALS = Number(process.env.TRIALS ?? 256);
const b = (s) => Buffer.from(s,"base64");
const backend = (v, msg) => {
  try {
    const k = createPublicKey({ key: b(v.key), format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519") return "REFUSE";
    return verify(null, msg ?? b(v.msg), k, b(v.sig)) ? "ACCEPT" : "REFUSE";
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
const summary={surface:"parent-unrepaired-backend",parent:"18b1a13c601cc362404dc6306fd8f4d1cc3e046e",trials:TRIALS,forgeable_within_budget:forgeable.length,positives_accepted:pos.filter(r=>r.got==="ACCEPT").length,forgeable_by_class:by,hostile:69,vectors:169};
writeFileSync(process.env.OUT+"/PARENT_BACKEND.json", JSON.stringify({summary,forgeable_ids:forgeable.map(r=>r.id),rows},null,2));
console.log(JSON.stringify(summary,null,2));
