// receipt-evm-v1 constants and shape (raven-receipt-evm / v1).
//
// The EVM sibling of receipt-v1: same canonical-JSON discipline, same signing
// recipe, same byte-exact disclaimer, DIFFERENT field set and domain string —
// a new namespace rather than a stretched receipt-v1, so both shapes stay
// closed and strict (unknown fields rejected). Status: PROPOSED contract with
// test-key vectors; no production endpoint signs this yet.

import {
  RECEIPT_DISCLAIMER,
  collectStrings,
  findForbiddenWords,
} from "./receiptV1.ts";

/** Signature domain — NEVER "raven-receipt" (that is the Solana receipt-v1). */
export const RECEIPT_EVM_DOMAIN = "raven-receipt-evm" as const;
export const RECEIPT_EVM_VERSION = "v1" as const;
export const RECEIPT_EVM_ID_PREFIX = "raven-receipt-evm-v1:" as const;
/** The disclaimer is shared byte-for-byte across receipt namespaces. */
export const RECEIPT_EVM_DISCLAIMER = RECEIPT_DISCLAIMER;

export { collectStrings, findForbiddenWords };

/** The 15 signed-preimage body fields, in documented order. */
export const RECEIPT_EVM_BODY_FIELDS = [
  "chain",
  "tokenAddress",
  "implementationAddress",
  "blockNumber",
  "blockHash",
  "timestamp",
  "rulesVersion",
  "findingTaxonomyVersion",
  "scopeChecksPerformed",
  "scopeChecksNotPerformed",
  "coverageGaps",
  "findings",
  "interpretations",
  "maxAgeSeconds",
  "disclaimer",
] as const;

export const RECEIPT_EVM_FIELDS = [
  ...RECEIPT_EVM_BODY_FIELDS,
  "payloadHash",
  "receiptId",
  "signature",
  "signerPublicKey",
] as const;

export interface EvmReceiptFinding {
  code: string;
  source: string;
  subject?: string;
  evidence?: Record<string, unknown>;
}

export interface EvmReceiptInterpretation {
  code: string;
  text: string;
  lang: string;
}

export interface ReceiptEvmV1Body {
  chain: string;
  tokenAddress: string;
  implementationAddress: string | null;
  blockNumber: number;
  blockHash: string;
  timestamp: string;
  rulesVersion: string;
  findingTaxonomyVersion: string;
  scopeChecksPerformed: string[];
  scopeChecksNotPerformed: string[];
  coverageGaps: string[];
  findings: EvmReceiptFinding[];
  interpretations: EvmReceiptInterpretation[];
  maxAgeSeconds: number;
  disclaimer: string;
}

export interface ReceiptEvmV1 extends ReceiptEvmV1Body {
  payloadHash: string;
  receiptId: string;
  signature: string;
  signerPublicKey: string;
}
