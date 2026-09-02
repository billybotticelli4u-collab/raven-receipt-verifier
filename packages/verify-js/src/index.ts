// raven-receipt-verifier — the open, dependency-free Raven receipt-v1 trust
// kernel.
//
// Verify a Raven receipt locally, offline, against a published key. This
// package contains ONLY verification: no producer, no signer, no scanner, no
// network, no advice. Verifying evidence is free and permissionless
// (Constitution #4).
//
// FROZEN PUBLIC SURFACE (0.1.0): exactly the Solana receipt-v1 kernel below.
// The receipt-evm-v1 and key-manifest modules in this source tree are
// PROPOSED drafts with no production signer or manifest; they are withheld
// from this export map on purpose (see src/proposed.ts) so the packed
// artifact makes no public compatibility promise for them. Do not re-export
// them here without an explicit owner-ratified surface decision.

export { canonicalJson, canonicalJsonStringify, CanonicalJsonError } from "./canonicalJson.ts";

export {
  verifyReceiptV1,
  type VerifyReceiptOptions,
  type VerifyReceiptResult,
} from "./verifyReceiptV1.ts";
export {
  verifyReceiptV1ForSubject,
  type ExpectedSolanaReceiptSubject,
  type SubjectReason,
  type VerifyReceiptForSubjectResult,
} from "./verifyReceiptV1ForSubject.ts";
export {
  evaluateReceiptRules,
  type ReceiptRulesResult,
  type RulesStatus,
} from "./receiptRules.ts";
export {
  RAVEN_PRODUCTION_TRUST_ANCHOR,
  ravenProductionTrustedKeys,
  type RavenTrustAnchorKey,
} from "./trustAnchor.ts";
export {
  classifyFindingCodesOutcome,
  type FindingOutcomeProjection,
  type FindingOutcomeProjectionResult,
  type SolanaOutcome,
} from "./outcomeProjection.ts";

export {
  RECEIPT_DOMAIN,
  RECEIPT_VERSION,
  RECEIPT_ID_PREFIX,
  RECEIPT_DISCLAIMER,
  RECEIPT_DISCLAIMER as RECEIPT_V1_DISCLAIMER,
  FORBIDDEN_WORDS,
  RECEIPT_BODY_FIELDS,
  RECEIPT_FIELDS,
  collectStrings,
  findForbiddenWords,
  type ReceiptFinding,
  type ReceiptInterpretation,
  type ReceiptV1Body,
  type ReceiptV1,
} from "./receiptV1.ts";

// Structural namespace routing (Solana vs EVM receipt shapes). A routing
// convenience only — the selected verifier still enforces its full strict
// shape. Retained in the public surface: it carries no PROPOSED verifier or
// manifest API.
export { detectReceiptNamespace, type ReceiptNamespace } from "./detect.ts";
