// verifyReceiptV1ForSubject — the partner-facing entrypoint of
// raven-receipt-verifier.
//
// The lower-level `verifyReceiptV1` answers ONE question: is this artifact a
// self-consistent, untampered Raven receipt (plus optional trust/freshness
// axes). It does NOT answer the question a partner actually has: "is this the
// evidence for the token I asked about?" A receipt for the right mint under a
// different token program is not the requested evidence, so the subject tuple
// is all three signed fields: chain, mintAddress and tokenProgramAddress.
//
// This wrapper keeps the axes separate BY CONSTRUCTION:
//  - it returns the kernel's VerifyReceiptResult unchanged (integrity `valid`,
//    trust `keyTrusted`, freshness `stale`, rules axis — never relabeled);
//  - it adds a SEPARATE binding axis: `subjectMatches` + `subjectReasons`;
//  - subject reasons never enter the integrity `reasons` array;
//  - the trust policy is REQUIRED here: omitting both trustedKeys and the
//    typed opt-out `allowUntrustedKey: true` is malformed configuration and
//    yields keyTrusted:false + trust_config_missing — never an absent axis.
//    Malformed/non-object policy yields trust_config_invalid.

import {
  canonicalDataSnapshot,
} from "./canonicalDataSnapshot.ts";
import {
  evaluateReceiptRules,
  isInspectableObject,
  type RulesStatus,
} from "./receiptRules.ts";
import { isCanonicalSolanaAddress } from "./solanaAddress.ts";
import {
  resolveKeyTrust,
  sanitizeOptions,
  verifyReceiptV1,
  type VerifyReceiptOptions,
  type VerifyReceiptResult,
} from "./verifyReceiptV1.ts";

/**
 * The subject tuple the caller requested. Closed JSON shape: exactly these
 * three own string-keyed fields. `chain` is the frozen 0.1.0 literal
 * "solana-mainnet" — the exact namespace the current receipt-v1 producer
 * signs. Any other expected chain is malformed caller input
 * (`expected_subject_invalid`), never a well-formed mismatch; future network
 * namespaces require an explicit reviewed surface expansion. Both addresses
 * must be canonical base58 encodings of exactly 32 decoded bytes.
 */
export interface ExpectedSolanaReceiptSubject {
  chain: "solana-mainnet";
  mintAddress: string;
  tokenProgramAddress: string;
}

export type SubjectReason =
  | "expected_subject_invalid"
  | "receipt_subject_unavailable"
  | "subject_chain_mismatch"
  | "subject_mint_mismatch"
  | "subject_token_program_mismatch";

export interface VerifyReceiptForSubjectResult extends VerifyReceiptResult {
  /**
   * true  — expected and signed chain/mint/program all match exactly;
   * false — both tuples readable and at least one field differs;
   * null  — binding could not be evaluated (malformed expected tuple or
   *         unreadable receipt subject); never silently true.
   */
  subjectMatches: boolean | null;
  /** Closed, ordered (chain → mint → program) binding reasons. */
  subjectReasons: SubjectReason[];
}

const EXPECTED_KEYS = ["chain", "mintAddress", "tokenProgramAddress"] as const;

/**
 * The only chain namespace the frozen 0.1.0 contract admits as caller input:
 * the exact string the current receipt-v1 producer signs. Module-private —
 * the public surface is the `ExpectedSolanaReceiptSubject` literal type.
 */
const SOLANA_MAINNET_CHAIN = "solana-mainnet";

/**
 * Validate the caller-supplied expected subject. Returns the normalized tuple
 * or null for ANY non-conforming shape: non-objects, arrays, missing or extra
 * own keys (string or symbol), inherited-only fields, non-string values, a
 * chain other than the frozen "solana-mainnet" literal, or non-canonical
 * addresses. Total over all inputs — proxy and accessor exceptions are
 * contained as null.
 */
const readExpectedSubject = (input: unknown): ExpectedSolanaReceiptSubject | null => {
  if (!isInspectableObject(input)) return null;
  try {
    const ownKeys = Reflect.ownKeys(input as object);
    if (ownKeys.length !== EXPECTED_KEYS.length) return null;
    const seen = new Set<string>();
    for (const key of ownKeys) {
      if (typeof key !== "string") return null; // symbol-keyed: not a JSON shape
      seen.add(key);
    }
    for (const required of EXPECTED_KEYS) {
      if (!seen.has(required)) return null;
    }
    const record = input as Record<string, unknown>;
    const chain = record.chain;
    const mintAddress = record.mintAddress;
    const tokenProgramAddress = record.tokenProgramAddress;
    if (chain !== SOLANA_MAINNET_CHAIN) return null;
    if (!isCanonicalSolanaAddress(mintAddress)) return null;
    if (!isCanonicalSolanaAddress(tokenProgramAddress)) return null;
    return {
      chain,
      mintAddress: mintAddress as string,
      tokenProgramAddress: tokenProgramAddress as string,
    };
  } catch {
    return null;
  }
};

/**
 * Read the signed subject tuple off the CAPTURED receipt snapshot (never the
 * caller's live object — see verifyReceiptV1ForSubject). The capture is a
 * frozen plain-data graph, so these reads cannot trigger hostile accessors;
 * the guard remains for totality. Null when any field is missing or not a
 * string.
 */
const readReceiptSubject = (
  receipt: unknown,
): { chain: string; mintAddress: string; tokenProgramAddress: string } | null => {
  if (!isInspectableObject(receipt)) return null;
  try {
    const record = receipt as Record<string, unknown>;
    const chain = record.chain;
    const mintAddress = record.mintAddress;
    const tokenProgramAddress = record.tokenProgramAddress;
    if (
      typeof chain !== "string" ||
      typeof mintAddress !== "string" ||
      typeof tokenProgramAddress !== "string"
    ) {
      return null;
    }
    return { chain, mintAddress, tokenProgramAddress };
  } catch {
    return null;
  }
};

/** Read a receipt's signer key without letting hostile accessors escape. */
const readSignerPublicKey = (receipt: unknown): string | null => {
  if (!isInspectableObject(receipt)) return null;
  try {
    const value = (receipt as Record<string, unknown>).signerPublicKey;
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
};

/**
 * Trust axis for the containment path, mirroring the kernel's settled
 * shape-failure semantics (#90): resolve the FULL policy, but a receipt with
 * no readable signer is never trusted by membership.
 */
const resolveContainmentTrust = (
  receipt: unknown,
  opts: VerifyReceiptOptions,
): { keyTrusted: boolean; reason?: string } => {
  const signerPublicKey = readSignerPublicKey(receipt);
  return resolveKeyTrust(signerPublicKey ?? "", opts);
};

const FALLBACK_RULES: {
  rulesVersion: string | null;
  rulesStatus: RulesStatus;
  rulesReasons: string[];
} = {
  rulesVersion: null,
  rulesStatus: "malformed",
  rulesReasons: ["malformed_rules_version"],
};

/**
 * Bounded result when the caller's live receipt object cannot even be
 * captured (a stateful/throwing accessor, revoked Proxy, cycle, or over-budget
 * graph). The hostile source is NEVER re-read — not for integrity, not for
 * trust, not for binding — so this resolves from the null receipt: integrity
 * invalid with a dedicated reason, rules malformed, trust per the caller's
 * policy but never established off an unreadable signer.
 */
const containmentResult = (
  opts: VerifyReceiptOptions,
): VerifyReceiptResult => {
  let rules: {
    rulesVersion: string | null;
    rulesStatus: RulesStatus;
    rulesReasons: string[];
  };
  try {
    rules = evaluateReceiptRules(null, false);
  } catch {
    rules = { ...FALLBACK_RULES, rulesReasons: [...FALLBACK_RULES.rulesReasons] };
  }
  const trust = resolveContainmentTrust(null, opts);
  return {
    valid: false,
    stale: false,
    reasons:
      trust.reason === undefined
        ? ["receipt_uninspectable"]
        : ["receipt_uninspectable", trust.reason],
    ...rules,
    keyTrusted: trust.keyTrusted,
  };
};

/**
 * Copy budget for the one stable receipt capture. Mirrors the reviewed ACP
 * receipt-body admission budget (16_384 nodes) — far beyond any legitimate
 * receipt, bounded enough to refuse a hostile graph before the kernel walks
 * it.
 */
const RECEIPT_SNAPSHOT_MAX_NODES = 16_384;

/**
 * Verify a receipt v1 AND bind it to the exact requested subject.
 *
 * Returns the kernel's result unchanged plus the subject axis. The trust
 * policy is required: callers must supply `trustedKeys` (an independently
 * pinned authorized key set — never same-host /pubkey material treated as
 * independent trust) or the explicit typed diagnostic opt-out
 * `allowUntrustedKey: true`. Omission yields keyTrusted:false +
 * trust_config_missing; malformed/non-object policy yields
 * keyTrusted:false + trust_config_invalid.
 *
 * Total over all inputs: hostile receipts, expected subjects and options
 * produce bounded outcomes, never exceptions.
 */
export const verifyReceiptV1ForSubject = (
  receipt: unknown,
  expectedSubject: unknown,
  options?: VerifyReceiptOptions,
): VerifyReceiptForSubjectResult => {
  const opts = sanitizeOptions(options);
  // Owner R1: do NOT normalise omission into allowUntrustedKey:false.
  // resolveKeyTrust reports trust_config_missing for genuine omission and
  // trust_config_invalid for malformed/non-object options.

  // ONE stable capture for BOTH axes. A live caller-supplied object can lie
  // per read: a stateful getter or Proxy trap can show the signed subject to
  // the integrity kernel and a different, requested-matching subject to a
  // later binding pass. The descriptor-safe snapshot reads each declared
  // field exactly once and deeply freezes the detached graph; integrity
  // verification and subject binding below consume only this capture. If the
  // capture itself fails, the outcome is the bounded uninspectable result and
  // the hostile source is never read again. Non-object receipts cannot be
  // hostile and pass straight through to the kernel's shape failure.
  let captured: unknown = receipt;
  let inspectable = true;
  if (isInspectableObject(receipt)) {
    try {
      captured = canonicalDataSnapshot(receipt, {
        maxNodes: RECEIPT_SNAPSHOT_MAX_NODES,
        label: "receipt-v1",
      });
    } catch {
      inspectable = false;
    }
  }

  let result: VerifyReceiptResult;
  if (!inspectable) {
    result = containmentResult(opts);
  } else {
    try {
      result = verifyReceiptV1(captured, opts);
    } catch {
      result = containmentResult(opts);
    }
  }

  let subjectMatches: boolean | null;
  const subjectReasons: SubjectReason[] = [];
  const expected = readExpectedSubject(expectedSubject);
  if (expected === null) {
    subjectMatches = null;
    subjectReasons.push("expected_subject_invalid");
  } else {
    const actual = inspectable ? readReceiptSubject(captured) : null;
    if (actual === null) {
      subjectMatches = null;
      subjectReasons.push("receipt_subject_unavailable");
    } else {
      // Stable chain → mint → program order; every applicable reason reported.
      if (actual.chain !== expected.chain) subjectReasons.push("subject_chain_mismatch");
      if (actual.mintAddress !== expected.mintAddress) {
        subjectReasons.push("subject_mint_mismatch");
      }
      if (actual.tokenProgramAddress !== expected.tokenProgramAddress) {
        subjectReasons.push("subject_token_program_mismatch");
      }
      subjectMatches = subjectReasons.length === 0;
    }
  }

  return { ...result, subjectMatches, subjectReasons };
};
