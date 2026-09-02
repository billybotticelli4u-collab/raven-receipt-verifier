// PROPOSED surface — INTERNAL re-exports, NOT part of the public export map.
//
// raven-receipt-verifier@0.1.0 publishes exactly one product contract: Solana
// receipt-v1 (see src/index.ts). The modules re-exported here are draft work
// whose own source comments label them PROPOSED: receipt-evm-v1 has no
// production signer, and the key-manifest chain has no production manifest.
// They stay compiled and tested so internal conformance (the cross-language
// comparator, the EVM vectors, the manifest chain tests) keeps covering them —
// but they are deliberately NOT reachable through the package's `exports` map,
// so the packed artifact makes no public compatibility promise for them.
//
// Internal consumers (conformance adapters, sibling packages, this package's
// own EVM/manifest tests) import from this module directly.

export {
  verifyReceiptEvmV1,
  type VerifyReceiptEvmResult,
} from "./verifyReceiptEvmV1.ts";
export {
  RECEIPT_EVM_DOMAIN,
  RECEIPT_EVM_VERSION,
  RECEIPT_EVM_ID_PREFIX,
  RECEIPT_EVM_DISCLAIMER,
  RECEIPT_EVM_BODY_FIELDS,
  RECEIPT_EVM_FIELDS,
  type EvmReceiptFinding,
  type EvmReceiptInterpretation,
  type ReceiptEvmV1Body,
  type ReceiptEvmV1,
} from "./receiptEvmV1.ts";
export {
  KEY_MANIFEST_DOMAIN,
  KEY_MANIFEST_VERSION,
  computeManifestHash,
  manifestSigningBytes,
  signKeyManifest,
  verifyManifestChain,
  extractTrustedKeys,
  type KeyManifestBody,
  type KeyScope,
  type KeyStatus,
  type ManifestChainResult,
  type ManifestKey,
  type ManifestSigner,
  type SignedKeyManifest,
} from "./keyManifest.ts";
