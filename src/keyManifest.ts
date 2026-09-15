// Key-manifest chain (maximal design §6.2) — how a consumer maintains Raven's
// trusted key set without trusting Raven's website on faith.
//
// A manifest is a canonical-JSON document listing keys with validity windows
// and status, hash-linked to its predecessor and SIGNED BY A KEY THE PREVIOUS
// MANIFEST LISTED AS ACTIVE (genesis: self-signed by a key it lists itself).
// A consumer pins the genesis hash once (e.g. at build time) and thereafter
// refreshes only along the signed chain — a manifest that does not chain from
// the pin is rejected loudly. ~100 lines to verify, by design.
//
// Status: PROPOSED. No production manifest is published yet; the live /pubkey
// endpoint remains the current key-distribution surface. Vectors here are
// test-key signed.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import { decodeCanonicalBase64, decodeCanonicalEd25519Spki } from "./verifyReceiptV1.ts";
import { assertEd25519SignatureDomain } from "./ed25519KeyDomain.ts";

import { canonicalJson } from "./canonicalJson.ts";

export const KEY_MANIFEST_DOMAIN = "raven-key-manifest" as const;
export const KEY_MANIFEST_VERSION = "v1" as const;

export type KeyStatus = "active" | "retiring" | "revoked";
export type KeyScope = "receipt-v1" | "receipt-evm-v1" | "attestation-v2" | "transparency-log";

export interface ManifestKey {
  keyId: string;
  publicKeyBase64: string; // SPKI DER, base64
  alg: "ed25519";
  scopes: KeyScope[];
  status: KeyStatus;
  notBefore?: string; // ISO-8601
  notAfter?: string;
}

/** The signed body of one manifest in the chain. */
export interface KeyManifestBody {
  manifestVersion: number; // 1 = genesis; strictly increments
  issuedAt: string;
  keys: ManifestKey[];
  previousManifestHash: string | null; // null ONLY for genesis
}

export interface SignedKeyManifest extends KeyManifestBody {
  manifestHash: string; // "sha256:" over canonical body
  signature: string; // ed25519 over the domain-separated envelope
  signerPublicKey: string;
}

export const computeManifestHash = (body: KeyManifestBody): string =>
  "sha256:" +
  createHash("sha256")
    .update(
      canonicalJson({
        manifestVersion: body.manifestVersion,
        issuedAt: body.issuedAt,
        keys: body.keys,
        previousManifestHash: body.previousManifestHash,
      }),
      "utf8",
    )
    .digest("hex");

export const manifestSigningBytes = (manifestHash: string): string =>
  canonicalJson({ domain: KEY_MANIFEST_DOMAIN, manifestHash, version: KEY_MANIFEST_VERSION });

/** Structural signer (same shape as the receipt signer). */
export interface ManifestSigner {
  publicKeyBase64: string;
  signBytes(message: string): string;
}

/** Producer-side helper: build + sign one manifest link. */
export const signKeyManifest = (
  body: KeyManifestBody,
  signer: ManifestSigner,
): SignedKeyManifest => {
  const manifestHash = computeManifestHash(body);
  return {
    ...body,
    manifestHash,
    signature: signer.signBytes(manifestSigningBytes(manifestHash)),
    signerPublicKey: signer.publicKeyBase64,
  };
};

const verifySignature = (m: SignedKeyManifest): boolean => {
  try {
    const pub = createPublicKey({
      key: decodeCanonicalEd25519Spki(m.signerPublicKey),
      format: "der",
      type: "spki",
    });
    if (pub.asymmetricKeyType !== "ed25519") return false;
    const signatureBytes = decodeCanonicalBase64(m.signature);
    assertEd25519SignatureDomain(signatureBytes);
    return cryptoVerify(
      null,
      Buffer.from(manifestSigningBytes(m.manifestHash), "utf8"),
      pub,
      signatureBytes,
    );
  } catch {
    return false;
  }
};

export interface ManifestChainResult {
  valid: boolean;
  reasons: string[];
  /** The final link's keys, when the chain is valid. */
  currentKeys: ManifestKey[];
}

/**
 * Verify a full manifest chain (genesis first). All-or-nothing: any broken
 * link invalidates the chain. Rules per link i:
 *   - manifestHash recomputes over the body;
 *   - genesis (i=0): previousManifestHash null, manifestVersion 1, and the
 *     signing key is listed ACTIVE in the genesis itself (self-signed root);
 *   - later links: previousManifestHash equals link i-1's hash, versions
 *     strictly increment, and the signing key was ACTIVE (or retiring) in
 *     link i-1 — old keys hand over to new, never the reverse;
 *   - the ed25519 signature verifies over the domain-separated envelope.
 * `pinnedGenesisHash`, when supplied, must equal link 0's hash — the consumer's
 * one root of trust.
 */
export const verifyManifestChain = (
  chain: readonly SignedKeyManifest[],
  opts: { pinnedGenesisHash?: string } = {},
): ManifestChainResult => {
  const reasons: string[] = [];
  if (chain.length === 0) return { valid: false, reasons: ["empty_chain"], currentKeys: [] };

  chain.forEach((m, i) => {
    if (computeManifestHash(m) !== m.manifestHash) {
      reasons.push(`link_${i}:manifest_hash_mismatch`);
    }
    if (!verifySignature(m)) {
      reasons.push(`link_${i}:signature_invalid`);
    }
    if (i === 0) {
      if (m.previousManifestHash !== null) reasons.push("link_0:genesis_must_have_null_previous");
      if (m.manifestVersion !== 1) reasons.push("link_0:genesis_version_must_be_1");
      const selfListed = m.keys.some(
        (k) => k.publicKeyBase64 === m.signerPublicKey && k.status === "active",
      );
      if (!selfListed) reasons.push("link_0:genesis_signer_not_listed_active");
      if (opts.pinnedGenesisHash !== undefined && opts.pinnedGenesisHash !== m.manifestHash) {
        reasons.push("link_0:pinned_genesis_hash_mismatch");
      }
    } else {
      const prev = chain[i - 1];
      if (m.previousManifestHash !== prev.manifestHash) {
        reasons.push(`link_${i}:previous_hash_mismatch`);
      }
      if (m.manifestVersion !== prev.manifestVersion + 1) {
        reasons.push(`link_${i}:version_not_incrementing`);
      }
      const authorized = prev.keys.some(
        (k) =>
          k.publicKeyBase64 === m.signerPublicKey &&
          (k.status === "active" || k.status === "retiring"),
      );
      if (!authorized) reasons.push(`link_${i}:signer_not_authorized_by_previous`);
    }
  });

  const valid = reasons.length === 0;
  return { valid, reasons, currentKeys: valid ? chain[chain.length - 1].keys : [] };
};

/**
 * Consumer-side: the trusted key set for a scope at a moment in time, from a
 * VERIFIED chain's current keys. Revoked keys never qualify; validity windows
 * are honored; `at` defaults to now.
 */
export const extractTrustedKeys = (
  keys: readonly ManifestKey[],
  opts: { scope?: KeyScope; at?: string } = {},
): Set<string> => {
  const at = opts.at === undefined ? Date.now() : Date.parse(opts.at);
  const out = new Set<string>();
  for (const k of keys) {
    if (k.status === "revoked") continue;
    if (opts.scope !== undefined && !k.scopes.includes(opts.scope)) continue;
    if (k.notBefore !== undefined && at < Date.parse(k.notBefore)) continue;
    if (k.notAfter !== undefined && at > Date.parse(k.notAfter)) continue;
    out.add(k.publicKeyBase64);
  }
  return out;
};
