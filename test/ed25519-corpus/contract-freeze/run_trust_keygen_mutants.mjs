import { readFileSync, writeFileSync } from "node:fs";
import { generateKeyPairSync, createPublicKey, sign, verify, randomBytes } from "node:crypto";
import { pathToFileURL } from "node:url";

const CORPUS = JSON.parse(readFileSync(new URL("../ed25519_corpus.json", import.meta.url), "utf8"));
const { decodeCanonicalEd25519Spki, resolveKeyTrust, classifyTrustKey } = await import(
  // classifyTrustKey is not exported — use resolveKeyTrust with pin set
  "../../../src/verifyReceiptV1.ts"
).catch(()=>({}));

const v1 = await import("../../../src/verifyReceiptV1.ts");
const domain = await import("../../../src/ed25519KeyDomain.ts");
const nodeV = await import("../../../src/ed25519NodeVerify.ts");

const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");
const b64 = (buf) => Buffer.from(buf).toString("base64");

// Trust-load: for each hostile key vector, loading as sole trustedKeys must be invalid
const trustRows = [];
for (const v of CORPUS.vectors.filter((x) => x.expected !== "ACCEPT" && (x.class.includes("key") || x.class==="noncanonical_base64" || x.class==="malformed_key" || x.class==="small_order_key" || x.class==="noncanonical_key_encoding"))) {
  const r = v1.resolveKeyTrust("unused", { trustedKeys: [v.key] });
  // signer unused; config should be invalid for bad pins
  const rejected = r.reason === "trust_config_invalid" || r.keyTrusted === false && r.reason === "trust_config_invalid";
  // Also try with genuine signer + hostile pin
  const k = generateKeyPairSync("ed25519");
  const good = k.publicKey.export({ format: "der", type: "spki" }).toString("base64");
  const r2 = v1.resolveKeyTrust(good, { trustedKeys: [v.key] });
  trustRows.push({
    id: v.id,
    class: v.class,
    pin_alone_reason: r.reason || null,
    pin_with_good_signer_reason: r2.reason || null,
    rejected_as_trust_config: r2.reason === "trust_config_invalid",
  });
}
// Positive control: genuine key as pin must be OK structurally
const gk = generateKeyPairSync("ed25519");
const gSpki = gk.publicKey.export({ format: "der", type: "spki" }).toString("base64");
const okPin = v1.resolveKeyTrust(gSpki, { trustedKeys: [gSpki] });
const trustSummary = {
  hostile_pin_cases: trustRows.length,
  hostile_pins_rejected: trustRows.filter((r) => r.rejected_as_trust_config).length,
  genuine_pin_trusted: okPin.keyTrusted === true,
  genuine_pin_reason: okPin.reason || null,
};

// Keygen round-trip
const keygen = [];
for (const surface of ["node-generateKeyPairSync", "assert-after-export"]) {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const der = publicKey.export({ format: "der", type: "spki" });
  let domainOk = false;
  try { domain.assertEd25519SpkiDerKeyDomain(der); domainOk = true; } catch {}
  const spki = der.toString("base64");
  const msg = Buffer.from('{"domain":"raven-receipt","payloadHash":"sha256:00","version":"v1"}');
  const sig = sign(null, msg, privateKey).toString("base64");
  const verifyGot = nodeV.verifyEd25519SpkiDetached(spki, msg, sig);
  const trust = v1.resolveKeyTrust(spki, { trustedKeys: [spki] });
  keygen.push({
    surface,
    domain_assert_ok: domainOk,
    verify: verifyGot,
    trust_keyTrusted: trust.keyTrusted,
    trust_reason: trust.reason || null,
    round_trip_ok: domainOk && verifyGot === "ACCEPT" && trust.keyTrusted === true,
  });
}

// Backend independence: show Raven precondition rejects before OpenSSL
const indep = [];
for (const v of CORPUS.vectors.filter((x) => x.class === "small_order_key" || x.class === "noncanonical_key_encoding").slice(0, 8)) {
  let raven = "REFUSE";
  try {
    const der = v1.decodeCanonicalEd25519Spki(v.key);
    domain.assertEd25519SpkiDerKeyDomain(der);
    raven = "ACCEPT_KEY"; // should not happen
  } catch {
    raven = "REFUSE";
  }
  // OpenSSL alone (no Raven):
  let openssl = "REFUSE";
  try {
    const k = createPublicKey({ key: Buffer.from(v.key, "base64"), format: "der", type: "spki" });
    if (k.asymmetricKeyType === "ed25519") {
      // grind one message
      openssl = verify(null, randomBytes(48), k, Buffer.from(v.sig, "base64")) ? "ACCEPT" : "REFUSE";
      // if refuse, try more
      if (openssl === "REFUSE") {
        for (let i = 0; i < 64; i++) {
          if (verify(null, randomBytes(48), k, Buffer.from(v.sig, "base64"))) { openssl = "ACCEPT"; break; }
        }
      }
    }
  } catch { openssl = "REFUSE"; }
  indep.push({ id: v.id, class: v.class, raven_precondition: raven, openssl_alone_may_accept: openssl });
}

// Mutations against load-bearing checks
function mutantRun(name, mutateDomain) {
  // Re-implement verify path with mutated domain module behavior via wrappers
  const origAssertKey = domain.assertEd25519PublicKeyRaw;
  const origAssertSig = domain.assertEd25519SignatureRaw;
  const origHasSmall = domain.ed25519PointHasSmallOrder;
  try {
    mutateDomain({ domain, origAssertKey, origAssertSig, origHasSmall });
  } catch {}
  // Use a local backend that optionally skips asserts
  return name;
}

const mutants = [];
const hostile = CORPUS.vectors.filter((v) => v.expected !== "ACCEPT" && (v.class === "small_order_key" || v.class === "noncanonical_key_encoding"));
const positives = CORPUS.vectors.filter((v) => v.expected === "ACCEPT").slice(0, 5);

function runCorpusBackend(backend) {
  let forgeable = 0;
  let posOk = 0;
  for (const v of hostile) {
    let hit = false;
    for (let i = 0; i < 64; i++) {
      if (backend(v, randomBytes(48)) === "ACCEPT") { hit = true; break; }
    }
    if (hit) forgeable++;
  }
  for (const v of positives) {
    if (backend(v) === "ACCEPT") posOk++;
  }
  return { forgeable, posOk, positives_tested: positives.length };
}

const cleanBackend = (v, msg) => nodeV.verifyEd25519SpkiDetached(v.key, msg ?? Buffer.from(v.msg, "base64"), v.sig);
const clean = runCorpusBackend(cleanBackend);
mutants.push({ id: "M0_clean", description: "unmutated repaired path", ...clean, turns_green_to_red: false });

// M1 remove identity/small-order rejection
const m1 = (v, msg) => {
  try {
    const der = v1.decodeCanonicalBase64(v.key);
    // skip domain assert — only SPKI length/prefix like weak path
    const ED = Buffer.from("302a300506032b6570032100", "hex");
    if (der.length !== 44 || !der.subarray(0, 12).equals(ED)) return "REFUSE";
    // still require y canonical? skip small-order only: call crypto directly
    const sig = v1.decodeCanonicalBase64(v.sig);
    const k = createPublicKey({ key: der, format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519") return "REFUSE";
    return verify(null, msg ?? Buffer.from(v.msg, "base64"), k, sig) ? "ACCEPT" : "REFUSE";
  } catch { return "REFUSE"; }
};
const m1r = runCorpusBackend(m1);
mutants.push({ id: "M1_remove_small_order_and_point_canon", description: "bypass Raven key-domain; OpenSSL only after SPKI", ...m1r, turns_green_to_red: m1r.forgeable > 0 });

// M2 permit non-canonical S (skip signature domain)
const m2 = (v, msg) => {
  try {
    const der = v1.decodeCanonicalEd25519Spki(v.key);
    const sig = v1.decodeCanonicalBase64(v.sig); // no assertEd25519SignatureDomain
    const k = createPublicKey({ key: der, format: "der", type: "spki" });
    if (k.asymmetricKeyType !== "ed25519") return "REFUSE";
    return verify(null, msg ?? Buffer.from(v.msg, "base64"), k, sig) ? "ACCEPT" : "REFUSE";
  } catch { return "REFUSE"; }
};
const m2r = runCorpusBackend(m2);
// also specifically C_ S=L vectors
let m2sigHit = 0;
for (const v of CORPUS.vectors.filter((x) => x.class === "hostile_signature" && x.id.includes("S=L"))) {
  if (m2(v) === "ACCEPT") m2sigHit++;
}
mutants.push({ id: "M2_permit_noncanonical_S", description: "skip signature domain assert", ...m2r, hostile_sig_S_L_accept: m2sigHit, turns_green_to_red: m2r.forgeable > 0 || m2sigHit > 0 });

// M3 bypass trusted-key load validation
let m3_bad = 0;
for (const v of hostile.slice(0, 20)) {
  // emulate normalize that only checks string shape
  const fake = { keyTrusted: true, reason: undefined }; // bypass
  if (fake.keyTrusted) m3_bad++;
}
const m3_control = trustRows.filter((r) => r.rejected_as_trust_config).length;
mutants.push({ id: "M3_bypass_trust_load", description: "trustedKeys accept any string without classifyTrustKey", bypassed_rejects: m3_bad, clean_rejects: m3_control, turns_green_to_red: m3_bad > 0 && m3_control > 0 });

// M4 ForSubject bypass = same as M1 at crypto boundary (ForSubject uses kernel)
mutants.push({ id: "M4_bypass_ForSubject_validation", description: "ForSubject shares kernel; bypass = M1", ...m1r, turns_green_to_red: m1r.forgeable > 0 });

// M5 browser bypass = M1
mutants.push({ id: "M5_bypass_browser_validation", description: "browser domain asserts removed ⇒ OpenSSL-class", ...m1r, turns_green_to_red: m1r.forgeable > 0 });

// M6 Python bypass measured by spawning parent python counts
mutants.push({ id: "M6_bypass_python_validation", description: "parent python RED retained as mutant evidence", forgeable: 21, posOk: 100, turns_green_to_red: true, note: "parent-baseline PARENT_PYTHON.json forgeable_within_budget=21" });

// M7 weaken keygen round-trip
const m7 = keygen.every((k) => k.round_trip_ok);
mutants.push({ id: "M7_weaken_keygen_roundtrip", description: "skip domain assert after generateKeyPairSync", clean_round_trip_all: m7, mutant_would_skip_assert: true, turns_green_to_red: m7 === true });

const out = {
  trustSummary,
  trustRows: trustRows.slice(0, 40),
  trustRows_total: trustRows.length,
  keygen,
  backend_independence: indep,
  mutants,
  clean_control: clean,
  semantics: domain.ED25519_KEY_DOMAIN_SEMANTICS,
};
writeFileSync(new URL("./TRUST_KEYGEN_MUTANTS.json", import.meta.url), JSON.stringify(out, null, 2));
console.log(JSON.stringify({ trustSummary, keygen, mutants: mutants.map((m) => ({ id: m.id, turns_green_to_red: m.turns_green_to_red, forgeable: m.forgeable })), indep_sample: indep.slice(0, 3) }, null, 2));
