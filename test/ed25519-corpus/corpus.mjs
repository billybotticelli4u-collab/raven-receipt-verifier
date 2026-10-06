// Hostile Ed25519 conformance corpus for Raven verifier surfaces.
// Written by the review lane. Vectors + expected Raven-level classification only.
// No repair, no implementation guidance.
import { generateKeyPairSync, sign, createHash, randomBytes } from "node:crypto";
import { writeFileSync } from "node:fs";

const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const le = (n) => { const b = Buffer.alloc(32); let x = n; for (let i=0;i<32;i++){ b[i]=Number(x & 0xffn); x >>= 8n; } return b; };
const hex = (s) => Buffer.from(s.replace(/\s/g,""), "hex");
const ED_SPKI = Buffer.from("302a300506032b6570032100","hex");
const spki = (raw) => Buffer.concat([ED_SPKI, raw]).toString("base64");
const MSG = Buffer.from('{"domain":"raven-receipt","payloadHash":"sha256:0000000000000000000000000000000000000000000000000000000000000000","version":"v1"}', "utf8");

// the eight canonical small-order encodings
const SMALL = {
  order1_identity: le(1n),
  order2:          le(P - 1n),
  order4_a:        hex("0000000000000000000000000000000000000000000000000000000000000000"),
  order4_b:        hex("0000000000000000000000000000000000000000000000000000000000000080"),
  order8_a:        hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05"),
  order8_b:        hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a"),
  order8_c:        hex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"),
  order8_d:        hex("c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa"),
};
const SIGS = {
  "R=identity,S=0": Buffer.concat([le(1n), Buffer.alloc(32)]),
  "R=order2,S=0":   Buffer.concat([le(P-1n), Buffer.alloc(32)]),
  "R=order8a,S=0":  Buffer.concat([SMALL.order8_a, Buffer.alloc(32)]),
  "R=identity,S=1": Buffer.concat([le(1n), le(1n)]),
};
const V = [];
const add = (id, cls, expect, note, keyB64, sigB64, msg = MSG.toString("base64"), keyFormat = "spki-ed25519") =>
  V.push({ id, class: cls, expected: expect, note, keyFormat, key: keyB64, sig: sigB64, msg });

// --- A. small-order public keys, canonical encodings (8 keys x 4 sigs = 32)
for (const [kn, raw] of Object.entries(SMALL))
  for (const [sn, sig] of Object.entries(SIGS))
    add(`A_${kn}__${sn}`, "small_order_key", "REJECT_KEY",
        "public key has order dividing 8; universal forgery class", spki(raw), sig.toString("base64"));

// --- B. non-canonical encodings that alias onto small-order points
const aliases = {
  "y=1+p":             le(1n + P),
  "y=1+p,signbit":     (() => { const b = le(1n + P); b[31] |= 0x80; return b; })(),
  "y=p (aliases 0)":   le(P),
  "y=p,signbit":       (() => { const b = le(P); b[31] |= 0x80; return b; })(),
  "y=p+1+p? (>2^255)": le(((1n<<255n) - 1n)),
  "y=0,signbit_set":   (() => { const b = Buffer.alloc(32); b[31] |= 0x80; return b; })(),
};
for (const [an, raw] of Object.entries(aliases))
  for (const sn of ["R=identity,S=0", "R=order2,S=0"])
    add(`B_alias_${an}__${sn}`, "noncanonical_key_encoding", "REJECT_KEY",
        "y >= p or sign-bit alias; an 8-entry blacklist does not catch these", spki(raw), SIGS[sn].toString("base64"));

// --- C. genuine key, hostile signature scalars
const K = generateKeyPairSync("ed25519");
const genuineSpki = K.publicKey.export({ format: "der", type: "spki" }).toString("base64");
const genuineSig = sign(null, MSG, K.privateKey);
const sigVariants = {
  "S=0":              Buffer.concat([genuineSig.subarray(0,32), Buffer.alloc(32)]),
  "S=L":              Buffer.concat([genuineSig.subarray(0,32), le(L)]),
  "S=L+1":            Buffer.concat([genuineSig.subarray(0,32), le(L + 1n)]),
  "S=2^255-1":        Buffer.concat([genuineSig.subarray(0,32), le((1n<<255n) - 1n)]),
  "S high bit set":   (() => { const s = Buffer.from(genuineSig); s[63] |= 0x80; return s; })(),
  "S+L (malleable)":  (() => { const s = Buffer.from(genuineSig); const cur = BigInt("0x"+Buffer.from(s.subarray(32)).reverse().toString("hex")); return Buffer.concat([s.subarray(0,32), le(cur + L)]); })(),
  "R=identity":       Buffer.concat([le(1n), genuineSig.subarray(32)]),
  "R=order2":         Buffer.concat([le(P-1n), genuineSig.subarray(32)]),
  "R zeroed":         Buffer.concat([Buffer.alloc(32), genuineSig.subarray(32)]),
  "one bit flipped":  (() => { const s = Buffer.from(genuineSig); s[10] ^= 0x01; return s; })(),
  "truncated 63B":    genuineSig.subarray(0,63),
  "extended 65B":     Buffer.concat([genuineSig, Buffer.from([0])]),
};
for (const [sn, sig] of Object.entries(sigVariants))
  add(`C_genuinekey__${sn}`, "hostile_signature", "REJECT_SIG",
      "well-formed prime-order key; signature must not verify", genuineSpki, sig.toString("base64"));

// --- D. malformed / wrong key material
const p256 = generateKeyPairSync("ec", { namedCurve: "prime256v1" }).publicKey.export({format:"der",type:"spki"}).toString("base64");
const rsa  = generateKeyPairSync("rsa", { modulusLength: 2048 }).publicKey.export({format:"der",type:"spki"}).toString("base64");
const ed448= generateKeyPairSync("ed448").publicKey.export({format:"der",type:"spki"}).toString("base64");
const x25519=generateKeyPairSync("x25519").publicKey.export({format:"der",type:"spki"}).toString("base64");
const gRaw = Buffer.from(genuineSpki,"base64").subarray(12);
const malformed = {
  "p256_key": p256, "rsa2048_key": rsa, "ed448_key": ed448, "x25519_key": x25519,
  "raw32_no_spki": gRaw.toString("base64"),
  "spki_trailing_byte": Buffer.concat([Buffer.from(genuineSpki,"base64"), Buffer.from([0])]).toString("base64"),
  "spki_truncated": Buffer.from(genuineSpki,"base64").subarray(0, 40).toString("base64"),
  "spki_null_params": Buffer.concat([hex("302e300906032b6570050003210"), Buffer.from([0]), gRaw]).toString("base64"),
  "spki_key_31_bytes": Buffer.concat([hex("3029300506032b657003200"), Buffer.from([0]), gRaw.subarray(0,31)]).toString("base64"),
  "empty": "",
};
for (const [mn, k] of Object.entries(malformed))
  add(`D_${mn}`, "malformed_key", "REJECT_KEY", "not a canonical Ed25519 SPKI public key", k, genuineSig.toString("base64"));

// --- E. base64 spelling of an otherwise genuine key (trust-identity axis)
const b64variants = {
  "unpadded": genuineSpki.replace(/=+$/,""),
  "whitespace": genuineSpki.slice(0,10) + "\n" + genuineSpki.slice(10),
  "tail_bits_mangled": genuineSpki.slice(0,-2) + "B=",
};
for (const [bn, k] of Object.entries(b64variants))
  add(`E_b64_${bn}`, "noncanonical_base64", "REJECT_KEY", "non-canonical base64 spelling must not resolve to a trusted key", k, genuineSig.toString("base64"));

// --- F. positive controls: 100 independently generated keypairs over real Raven preimages
for (let i = 0; i < 100; i++) {
  const kp = generateKeyPairSync("ed25519");
  const ph = "sha256:" + createHash("sha256").update(randomBytes(32)).digest("hex");
  const msg = Buffer.from(`{"domain":"raven-receipt","payloadHash":"${ph}","version":"v1"}`, "utf8");
  add(`F_positive_${String(i).padStart(3,"0")}`, "genuine", "ACCEPT", "legitimate keypair, genuine signature over a real Raven preimage",
      kp.publicKey.export({format:"der",type:"spki"}).toString("base64"),
      sign(null, msg, kp.privateKey).toString("base64"), msg.toString("base64"));
}
writeFileSync("ed25519_corpus.json", JSON.stringify({
  name: "raven-hostile-ed25519-corpus", version: "1.0.0", generated_utc: new Date().toISOString(),
  authored_by: "independent review lane (not the repair lane)",
  classification_rule: {
    REJECT_KEY: "key is not a canonical, on-curve, prime-order-subgroup Ed25519 point, or not a canonical Ed25519 SPKI, or a non-canonical base64 spelling — must be refused BEFORE any backend signature check",
    REJECT_SIG: "key domain is fine; the signature must not verify",
    ACCEPT:     "genuine key, genuine signature"
  },
  counts: V.reduce((a,v)=>(a[v.expected]=(a[v.expected]||0)+1,a),{}),
  vectors: V
}, null, 1));
console.log("vectors:", V.length, V.reduce((a,v)=>(a[v.expected]=(a[v.expected]||0)+1,a),{}));
console.log("hostile (non-positive):", V.filter(v=>v.class!=="genuine").length);
