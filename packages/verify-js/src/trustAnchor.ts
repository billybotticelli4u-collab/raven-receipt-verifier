// Production trust anchor — embedded for the authenticated onboarding path.
//
// WHY THIS FILE EXISTS (mission RAVEN-BUZZ-REVENUE-01, review finding
// 2026-08-31): the authenticated commercial/onboarding handoff names the
// exact package, version and integrity a customer intends to trust. npm
// provenance authenticates package/source lineage, but cannot select the
// intended Raven key by itself. This constant lets that authenticated package
// carry the exact production anchor for offline verification. /pubkey and
// security.html remain cross-checks. Rotation REQUIRES a newly authenticated
// package release by design.
//
// keyId is a public function of the key (rvk_ + first 16 hex of sha256 over
// the base64 SPKI string). Matching keyId proves self-consistency, NOT
// authenticity — anyone can mint a key and compute its keyId. Initial trust
// comes from the authenticated package/version/integrity handoff; /pubkey and
// security.html cross-check this constant, never replace that handoff.

export interface RavenTrustAnchorKey {
  readonly keyId: string;
  readonly alg: "ed25519";
  /** Canonical Ed25519 SubjectPublicKeyInfo, DER, base64 (44 bytes decoded). */
  readonly publicKeyBase64: string;
  /** sha256 over the decoded SPKI DER bytes, hex. */
  readonly spkiSha256Hex: string;
  /** sha256 over the raw 32-byte Ed25519 public key, hex. */
  readonly rawKeySha256Hex: string;
  /** Where and when this material was measured from production. */
  readonly measuredFrom: string;
  readonly measuredAt: string;
}

export const RAVEN_PRODUCTION_TRUST_ANCHOR: readonly RavenTrustAnchorKey[] = Object.freeze([
  Object.freeze({
    keyId: "rvk_c2997e90215279c2",
    alg: "ed25519",
    publicKeyBase64: "MCowBQYDK2VwAyEASGJt4Ilx2Z6g0BVC1VQIfaUcV0nr8WB1J45/8vfje6w=",
    spkiSha256Hex: "7b6fd83d116e69235da5cd0bc4f61d6497196c9bbcdc99ca42d7f501c9d6f3ce",
    rawKeySha256Hex: "8a80853c0a0f8343f4580fd2a8021f53b673ac492b193a19e739c94fd2eb0b48",
    measuredFrom: "https://raven-hosted-verifier.onrender.com/pubkey + ravenattest.com/security.html (byte-identical)",
    measuredAt: "2026-08-31T20:47:14Z",
  } as const),
]);

/**
 * The production trusted-key set, ready for `verifyReceiptV1(..., { trustedKeys })`.
 * A fresh mutable Set each call — callers may add their own keys without
 * mutating the anchor.
 */
export function ravenProductionTrustedKeys(): Set<string> {
  return new Set(RAVEN_PRODUCTION_TRUST_ANCHOR.map((key) => key.publicKeyBase64));
}
