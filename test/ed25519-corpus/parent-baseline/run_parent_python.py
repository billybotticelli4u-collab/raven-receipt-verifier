#!/usr/bin/env python3
import json, os, sys, base64, secrets
from pathlib import Path
PARENT = Path(os.environ["PARENT_WT"]) / "reference-verifiers/python"
sys.path.insert(0, str(PARENT))
# Import parent module under a unique name to avoid colliding with repaired tree
import importlib.util
spec = importlib.util.spec_from_file_location("raven_verify_parent", PARENT / "raven_verify.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
C = json.loads(Path(os.environ["CORPUS"]).read_text())
TRIALS = int(os.environ.get("TRIALS", "256"))

def backend(v, msg=None):
    try:
        raw = mod.raw_key_from_spki_base64(v["key"])
        sig = mod._decode_canonical_base64(v["sig"])
        m = msg if msg is not None else base64.b64decode(v["msg"])
        return "ACCEPT" if mod.ed25519_verify(raw, m, sig) else "REFUSE"
    except Exception:
        return "REFUSE"

rows=[]
for v in C["vectors"]:
    if v["expected"]=="ACCEPT":
        rows.append({"id":v["id"],"class":v["class"],"expect":"ACCEPT","got":backend(v),"grinds":None}); continue
    hit=None
    for i in range(TRIALS):
        if backend(v, secrets.token_bytes(48))=="ACCEPT":
            hit=i+1; break
    rows.append({"id":v["id"],"class":v["class"],"expect":"REFUSE","got":"REFUSE" if hit is None else "ACCEPT","grinds":hit})
forgeable=[r for r in rows if r["expect"]=="REFUSE" and r["got"]=="ACCEPT"]
pos=[r for r in rows if r["expect"]=="ACCEPT"]
by={}
for r in forgeable: by[r["class"]]=by.get(r["class"],0)+1
summary={"surface":"parent-python","parent":"18b1a13c601cc362404dc6306fd8f4d1cc3e046e","trials":TRIALS,"forgeable_within_budget":len(forgeable),"positives_accepted":sum(1 for r in pos if r["got"]=="ACCEPT"),"forgeable_by_class":by}
Path(os.environ["OUT"],"PARENT_PYTHON.json").write_text(json.dumps({"summary":summary,"forgeable_ids":[r["id"] for r in forgeable],"rows":rows},indent=2))
print(json.dumps(summary, indent=2))
