import { readFileSync, writeFileSync } from "node:fs";
import { createPublicKey, verify, randomBytes } from "node:crypto";

const CORPUS = JSON.parse(readFileSync(new URL("../ed25519_corpus.json", import.meta.url), "utf8"));
const v1 = await import("../../../src/verifyReceiptV1.ts");
const domain = await import("../../../src/ed25519KeyDomain.ts");
const nodeV = await import("../../../src/ed25519NodeVerify.ts");

const hostileKey = CORPUS.vectors.filter((v) =>
  ["small_order_key", "noncanonical_key_encoding", "malformed_key", "noncanonical_base64"].includes(v.class)
);
const hostileSig = CORPUS.vectors.filter((v) => v.class === "hostile_signature");

function ravenKey(v) {
  try {
    const der = v1.decodeCanonicalEd25519Spki(v.key);
    domain.assertEd25519SpkiDerKeyDomain(der);
    return "ACCEPT_KEY";
  } catch {
    return "REFUSE";
  }
}
function ravenSig(v) {
  try {
    const sig = v1.decodeCanonicalBase64(v.sig);
    domain.assertEd25519SignatureDomain(sig);
    return "ACCEPT_SIG";
  } catch {
    return "REFUSE";
  }
}
function opensslKeyMayAccept(v, trials = 64) {
  try {
    const der = Buffer.from(v.key, "base64");
    const k = createPublicKey({ key: der, format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519") return "REFUSE";
    const sig = Buffer.from(v.sig, "base64");
    for (let i = 0; i < trials; i++) {
      if (verify(null, randomBytes(48), k, sig)) return "ACCEPT";
    }
    return "REFUSE";
  } catch {
    return "REFUSE";
  }
}

const indep = hostileKey.map((v) => ({
  id: v.id,
  class: v.class,
  raven_precondition: ravenKey(v),
  openssl_alone_may_accept: opensslKeyMayAccept(v),
}));

const sigIndep = hostileSig.map((v) => {
  let openssl = "REFUSE";
  try {
    const k = createPublicKey({ key: Buffer.from(v.key, "base64"), format: "der", type: "spki" });
    openssl = verify(null, Buffer.from(v.msg, "base64"), k, Buffer.from(v.sig, "base64")) ? "ACCEPT" : "REFUSE";
  } catch {
    openssl = "REFUSE";
  }
  return { id: v.id, class: v.class, raven_precondition: ravenSig(v), openssl_verify: openssl };
});

function m2_permissive(v) {
  try {
    const der = v1.decodeCanonicalEd25519Spki(v.key);
    domain.assertEd25519SpkiDerKeyDomain(der);
    const sig = v1.decodeCanonicalBase64(v.sig);
    if (sig.length !== 64) return "REFUSE";
    // MUTANT: skip assertEd25519SignatureDomain; pretend backend accepts any 64B
    return "ACCEPT";
  } catch {
    return "REFUSE";
  }
}
function clean_sig(v) {
  return nodeV.verifyEd25519SpkiDetached(v.key, Buffer.from(v.msg, "base64"), v.sig);
}

const m2_rows = hostileSig.map((v) => ({
  id: v.id,
  clean: clean_sig(v),
  mutant_permit_noncanonical_S_or_any_64B: m2_permissive(v),
}));
const m2_turns_red = m2_rows.some(
  (r) => r.clean === "REFUSE" && r.mutant_permit_noncanonical_S_or_any_64B === "ACCEPT"
);

// Split M1a identity-only vs M1b small-order: measure forgeable with OpenSSL after SPKI+canon decompress but no small-order
function opensslAfterCanonNoSmallOrder(v, trials = 64) {
  try {
    const der = v1.decodeCanonicalEd25519Spki(v.key);
    const raw = der.subarray(12);
    domain.decompressCanonicalEd25519Point(raw); // canon only
    // skip small-order
    const sig = Buffer.from(v.sig, "base64");
    const k = createPublicKey({ key: der, format: "der", type: "spki" });
    for (let i = 0; i < trials; i++) {
      if (verify(null, randomBytes(48), k, sig)) return "ACCEPT";
    }
    return "REFUSE";
  } catch {
    return "REFUSE";
  }
}
const smallOrder = CORPUS.vectors.filter((v) => v.class === "small_order_key");
let m1b_forgeable = 0;
for (const v of smallOrder) {
  let hit = false;
  for (let t = 0; t < 64; t++) {
    if (opensslAfterCanonNoSmallOrder(v, 1) === "ACCEPT") {
      hit = true;
      break;
    }
  }
  // better: single function with trials
  if (opensslAfterCanonNoSmallOrder(v, 64) === "ACCEPT") m1b_forgeable++;
}

const payload = {
  key_cases: indep,
  signature_cases: sigIndep,
  summary: {
    key_raven_refuse: indep.filter((x) => x.raven_precondition === "REFUSE").length,
    key_openssl_accept: indep.filter((x) => x.openssl_alone_may_accept === "ACCEPT").length,
    raven_refuse_openssl_accept: indep.filter(
      (x) => x.raven_precondition === "REFUSE" && x.openssl_alone_may_accept === "ACCEPT"
    ).length,
    sig_raven_refuse: sigIndep.filter((x) => x.raven_precondition === "REFUSE").length,
    sig_openssl_accept: sigIndep.filter((x) => x.openssl_verify === "ACCEPT").length,
  },
  m1b_remove_small_order_only: { forgeable_within_budget_64: m1b_forgeable, turns_green_to_red: m1b_forgeable > 0 },
  m2: { turns_green_to_red: m2_turns_red, rows: m2_rows },
};
writeFileSync(new URL("./BACKEND_INDEPENDENCE.json", import.meta.url), JSON.stringify(payload, null, 2));
console.log(
  JSON.stringify(
    {
      key_total: indep.length,
      raven_refuse_openssl_accept: payload.summary.raven_refuse_openssl_accept,
      m1b_forgeable,
      m2_turns_red,
      m2_accept_count: m2_rows.filter((r) => r.mutant_permit_noncanonical_S_or_any_64B === "ACCEPT").length,
    },
    null,
    2
  )
);
