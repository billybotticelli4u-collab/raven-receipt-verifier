/**
 * Ed25519 key-domain predicate.
 *
 * Named semantics: **libsodium `crypto_sign_verify_detached`**
 * (canonicalize point encoding; reject small-order public keys; reject
 * non-canonical scalar S). Applied before any Node `crypto.verify` /
 * WebCrypto call so OpenSSL line differences cannot re-open the forgery class.
 *
 * Trust-identity (non-canonical base64 spellings) is enforced by the caller’s
 * canonical base64 decoder; this module assumes already-decoded raw bytes.
 */
const P = (1n << 255n) - 19n;
const L = (1n << 252n) + 27742317777372353535851937790883648493n;
const D = (-121665n * modInv(121666n, P)) % P;
const I = modPow(2n, (P - 1n) / 4n, P);

export const ED25519_KEY_DOMAIN_SEMANTICS = "libsodium crypto_sign_verify_detached" as const;

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let b = ((base % m) + m) % m;
  let e = exp;
  let r = 1n;
  while (e > 0n) {
    if (e & 1n) r = (r * b) % m;
    b = (b * b) % m;
    e >>= 1n;
  }
  return r;
}

function modInv(a: bigint, m: bigint): bigint {
  return modPow(a, m - 2n, m);
}

function leBytesToBigInt(buf: Uint8Array): bigint {
  let x = 0n;
  for (let i = 0; i < buf.length; i++) x |= BigInt(buf[i]!) << (8n * BigInt(i));
  return x;
}

function bigIntToLe32(n: bigint): Uint8Array {
  const out = new Uint8Array(32);
  let x = n;
  for (let i = 0; i < 32; i++) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

type ExtPoint = readonly [bigint, bigint, bigint, bigint]; // X,Y,Z,T

const IDENTITY: ExtPoint = [0n, 1n, 1n, 0n];

function edwardsAdd(p: ExtPoint, q: ExtPoint): ExtPoint {
  const [x1, y1, z1, t1] = p;
  const [x2, y2, z2, t2] = q;
  const a = ((y1 - x1) * (y2 - x2)) % P;
  const b = ((y1 + x1) * (y2 + x2)) % P;
  const c = (2n * t1 * t2 * D) % P;
  const dd = (2n * z1 * z2) % P;
  const e = (b - a) % P;
  const f = (dd - c) % P;
  const g = (dd + c) % P;
  const h = (b + a) % P;
  return [(((e * f) % P) + P) % P, (((g * h) % P) + P) % P, (((f * g) % P) + P) % P, (((e * h) % P) + P) % P];
}

function edwardsDouble(p: ExtPoint): ExtPoint {
  return edwardsAdd(p, p);
}

function pointEqual(p: ExtPoint, q: ExtPoint): boolean {
  return (
    (((p[0] * q[2] - q[0] * p[2]) % P) + P) % P === 0n &&
    (((p[1] * q[2] - q[1] * p[2]) % P) + P) % P === 0n
  );
}

function xrecover(y: bigint): bigint {
  const yy = (y * y) % P;
  const u = (yy - 1n + P) % P;
  const v = (D * yy + 1n) % P;
  const xx = (u * modInv(v, P)) % P;
  let x = modPow(xx, (P + 3n) / 8n, P);
  if ((x * x - xx) % P !== 0n) x = (x * I) % P;
  if ((x * x - xx) % P !== 0n) throw new Error("not a curve point");
  return x;
}

/** Decompress 32-byte encoding; reject non-canonical y≥p and non-points. */
export function decompressCanonicalEd25519Point(enc: Uint8Array): ExtPoint {
  if (enc.length !== 32) throw new Error("bad point length");
  const y = leBytesToBigInt(enc) & ((1n << 255n) - 1n);
  const sign = enc[31]! >> 7;
  if (y >= P) throw new Error("noncanonical ed25519 point encoding");
  let x = xrecover(y);
  if ((x & 1n) !== BigInt(sign)) x = (P - x) % P;
  // Re-encode and require byte-identity (canonical encoding).
  const recomputed = encodeCanonicalEd25519Point(x, y);
  for (let i = 0; i < 32; i++) {
    if (recomputed[i] !== enc[i]) throw new Error("noncanonical ed25519 point encoding");
  }
  return [x, y, 1n, (x * y) % P];
}

function encodeCanonicalEd25519Point(x: bigint, y: bigint): Uint8Array {
  const out = bigIntToLe32(y);
  if (x & 1n) out[31] = (out[31]! | 0x80) >>> 0;
  else out[31] = out[31]! & 0x7f;
  return out;
}

/** True iff P has order dividing 8 (libsodium ge25519_has_small_order class). */
export function ed25519PointHasSmallOrder(p: ExtPoint): boolean {
  // [8]P == identity
  let q = edwardsDouble(p);
  q = edwardsDouble(q);
  q = edwardsDouble(q);
  return pointEqual(q, IDENTITY);
}

export function assertEd25519PublicKeyRaw(raw: Uint8Array): void {
  const p = decompressCanonicalEd25519Point(raw);
  if (ed25519PointHasSmallOrder(p)) throw new Error("ed25519 public key has small order");
}

export function assertEd25519SignatureRaw(sig: Uint8Array): void {
  if (sig.length !== 64) throw new Error("bad signature length");
  // R must be a canonical curve point (libsodium rejects non-canonical R).
  decompressCanonicalEd25519Point(sig.subarray(0, 32));
  const s = leBytesToBigInt(sig.subarray(32));
  if (s >= L) throw new Error("noncanonical ed25519 scalar S");
}

/** Raw 32-byte key from already-validated 44-byte Ed25519 SPKI DER. */
export function rawEd25519FromSpkiDer(der: Uint8Array): Uint8Array {
  if (der.length !== 44) throw new Error("not an Ed25519 SPKI key");
  return der.subarray(12);
}

export function assertEd25519SpkiDerKeyDomain(der: Uint8Array): void {
  assertEd25519PublicKeyRaw(rawEd25519FromSpkiDer(der));
}

export function assertEd25519SignatureDomain(sig: Uint8Array): void {
  assertEd25519SignatureRaw(sig);
}
