// Raven Receipt v1 — open verification library (SPEC §8).
//
// Byte-for-byte port of `apps/launchguard-acp/src/receipt/verifyReceiptV1.ts`, with
// imports rewired to this package's local canonicalJson + constants. It depends on
// NOTHING proprietary and NOTHING networked: only `node:crypto`. The closed signer
// GENERATES receipts; this library VERIFIES them.
//
// Result contract (matches the production verifier):
//   { valid, stale, reasons, rulesVersion, rulesStatus, rulesReasons, keyTrusted? }
// `valid` is gated ONLY by checks 1–5 (shape, disclaimer, forbidden words, payload
// hash + receiptId, signature). Key trust (6) and freshness (7) are reported but
// NON-FATAL — a self-consistent signature from an untrusted key is still a valid
// signature, and a stale receipt is still an authentic one. Rules conformance is
// a third independent axis and never changes those historical fields.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

import { canonicalJson } from "./canonicalJson.ts";
import {
  evaluateReceiptRules,
  isInspectableObject,
  type ReceiptRulesResult,
  type RulesStatus,
} from "./receiptRules.ts";
import {
  RECEIPT_DOMAIN,
  RECEIPT_VERSION,
  RECEIPT_ID_PREFIX,
  RECEIPT_DISCLAIMER,
  RECEIPT_BODY_FIELDS,
  RECEIPT_FIELDS,
  collectStrings,
  findForbiddenWords,
  type ReceiptV1Body,
} from "./receiptV1.ts";

const PUBLIC_KEY_CACHE_MAX = 64;
const publicKeyCache = new Map<string, ReturnType<typeof createPublicKey>>();

// RFC 4648 standard Base64, including canonical padding and pad bits. Buffer's
// permissive decoder must not turn a noncanonical wire spelling into a valid
// signature on Node while browser and Python reject the same receipt.
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

const decodeCanonicalBase64 = (value: string): Buffer => {
  if (!CANONICAL_BASE64.test(value)) throw new Error("noncanonical base64");
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) throw new Error("noncanonical base64");
  return decoded;
};

const decodeCanonicalEd25519Spki = (value: string): Buffer => {
  const decoded = decodeCanonicalBase64(value);
  if (
    decoded.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !decoded.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error("not a canonical Ed25519 SPKI key");
  }
  return decoded;
};

const cachePublicKey = (
  signerPublicKey: string,
  publicKey: ReturnType<typeof createPublicKey>,
): void => {
  if (publicKeyCache.size >= PUBLIC_KEY_CACHE_MAX) {
    const oldest = publicKeyCache.keys().next().value;
    if (oldest !== undefined) publicKeyCache.delete(oldest);
  }
  publicKeyCache.set(signerPublicKey, publicKey);
};

export interface VerifyReceiptOptions {
  /** "Now" for freshness; ISO string or Date. Defaults to the current time. */
  now?: string | Date;
  /**
   * Trusted signer public keys (base64 SPKI DER), as a Set or a plain string
   * array — the shape any caller loading keys from JSON, env or /pubkey will
   * hold. When provided, key trust is reported via `keyTrusted`. Trust is
   * NON-FATAL — it never gates `valid`.
   *
   * Every malformed value fails closed and typed: a non-collection (number,
   * string, plain object, explicit null) or any non-string collection member
   * yields `keyTrusted: false` with `trust_config_invalid`. No exception
   * escapes for any input.
   */
  trustedKeys?: ReadonlySet<string> | readonly string[] | null;
  /**
   * Typed relationship to trust evaluation when no `trustedKeys` are
   * supplied: `true` opts out deliberately (`key_trust_not_evaluated`);
   * `false` declares untrusted keys unacceptable — with no keys supplied that
   * is a contract error on the trust axis (`trust_config_invalid`), never a
   * silent pass. When both options are omitted, the historical
   * not-evaluated behavior is preserved (`keyTrusted` absent).
   */
  allowUntrustedKey?: boolean;
}

/**
 * Normalize a caller-supplied trustedKeys collection to a Set of strings.
 * Returns null on ANY malformed input: non-collections, and collections with
 * any non-string member. Validation is total — no exception escapes for any
 * value.
 */
export const normalizeTrustedKeys = (
  input: ReadonlySet<string> | readonly string[] | null | undefined,
): ReadonlySet<string> | null => {
  // Exception containment: a hostile collection (a revoked Proxy, a Set
  // subclass whose iterator throws, a throwing getter) must degrade to the
  // typed malformed outcome — no exception escapes for any input value.
  try {
    const entries: unknown = input instanceof Set ? [...input] : input;
    if (!Array.isArray(entries)) return null;
    const out = new Set<string>();
    for (const entry of entries) {
      if (typeof entry !== "string") return null;
      out.add(entry);
    }
    return out;
  } catch {
    return null;
  }
};

/**
 * Resolve the key-trust axis (check 6, NON-FATAL). Shared by the Solana and
 * EVM verifiers so both enforce the same trust-input contract.
 */
export const resolveKeyTrust = (
  signerPublicKey: string,
  opts: Pick<VerifyReceiptOptions, "trustedKeys" | "allowUntrustedKey">,
): { keyTrusted: boolean | undefined; reason?: string } => {
  // A supplied allowUntrustedKey that is not a boolean (realistic for
  // env-derived strings such as "false") is malformed trust configuration:
  // fail closed and typed, never silently treat it as omitted. This check
  // runs before the trustedKeys path so a malformed flag is invalid even
  // when valid keys are supplied.
  if (opts.allowUntrustedKey !== undefined && typeof opts.allowUntrustedKey !== "boolean") {
    return { keyTrusted: false, reason: "trust_config_invalid" };
  }
  if (opts.trustedKeys !== undefined) {
    const keys = normalizeTrustedKeys(opts.trustedKeys);
    if (keys === null) return { keyTrusted: false, reason: "trust_config_invalid" };
    const keyTrusted = keys.has(signerPublicKey);
    return keyTrusted ? { keyTrusted: true } : { keyTrusted: false, reason: "key_untrusted" };
  }
  if (opts.allowUntrustedKey === true) {
    return { keyTrusted: false, reason: "key_trust_not_evaluated" };
  }
  if (opts.allowUntrustedKey === false) {
    return { keyTrusted: false, reason: "trust_config_invalid" };
  }
  return { keyTrusted: undefined };
};

/**
 * Read the signer public key off a receipt that has NOT passed shape. Returns
 * null when the field is missing or not a string, and contains any exception a
 * hostile receipt raises on property access (throwing getter, revoked Proxy) —
 * the trust axis must produce an outcome for every input, never an exception.
 */
const readSignerPublicKey = (receipt: unknown): string | null => {
  if (receipt === null || typeof receipt !== "object") return null;
  try {
    const value = (receipt as Record<string, unknown>).signerPublicKey;
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
};

/**
 * Resolve the FULL trust axis on the receipt-shape early-return paths.
 *
 * Trust is a separate NON-FATAL axis, so it is reported whenever the caller
 * supplied a trust option — `keyTrusted` is documented as present in exactly
 * that case, and that promise cannot be conditional on receipt validity. The
 * main path already resolves trust after a FAILED signature check; a shape
 * failure must not report less.
 *
 * When the receipt carries no usable `signerPublicKey` there is nothing a
 * well-formed `trustedKeys` set can legitimately match, so trust resolves
 * closed (`keyTrusted: false`, `key_untrusted`). The membership test is skipped
 * entirely in that case so a caller-supplied set can never make a receipt with
 * no signer look trusted by matching a placeholder.
 *
 * `resolveKeyTrust` remains the single source of truth for every outcome.
 * This mirrors the ACP verifier's settled semantics (#90) so the two kernels
 * do not diverge on the trust axis.
 */
const resolveShapeFailureTrust = (
  receipt: unknown,
  opts: Pick<VerifyReceiptOptions, "trustedKeys" | "allowUntrustedKey">,
): { keyTrusted: boolean | undefined; reason?: string } => {
  // No policy supplied: the receipt is not inspected at all, so the shape
  // result is byte-for-byte what it was before this change. Trust resolution
  // is the ONLY reason this function reads a shape-failed receipt.
  if (opts.trustedKeys === undefined && opts.allowUntrustedKey === undefined) {
    return { keyTrusted: undefined };
  }
  const signerPublicKey = readSignerPublicKey(receipt);
  const trust = resolveKeyTrust(signerPublicKey ?? "", opts);
  if (signerPublicKey === null && trust.keyTrusted === true) {
    return { keyTrusted: false, reason: "key_untrusted" };
  }
  return trust;
};

export interface VerifyReceiptResult {
  valid: boolean;
  stale: boolean;
  reasons: string[];
  /** Exact signed Solana rules identity, when structurally extractable. */
  rulesVersion: string | null;
  /** Semantic conformance, independent of integrity/freshness/key trust. */
  rulesStatus: RulesStatus;
  /** Closed, ordered semantic reasons; never mixed into `reasons`. */
  rulesReasons: string[];
  /** Present when `trustedKeys` or `allowUntrustedKey` was supplied. */
  keyTrusted?: boolean;
}

const malformedRulesResult = (): ReceiptRulesResult => ({
  rulesVersion: null,
  rulesStatus: "malformed",
  rulesReasons: ["malformed_rules_version"],
});

const safeEvaluateReceiptRules = (receipt: unknown, coreValid: boolean): ReceiptRulesResult => {
  try {
    return evaluateReceiptRules(receipt, coreValid);
  } catch {
    return malformedRulesResult();
  }
};

const shapeNotObjectResult = (
  receipt: unknown,
  opts: VerifyReceiptOptions,
): VerifyReceiptResult => {
  const trust = resolveShapeFailureTrust(receipt, opts);
  return {
    valid: false,
    stale: false,
    reasons:
      trust.reason === undefined
        ? ["shape_not_an_object"]
        : ["shape_not_an_object", trust.reason],
    ...safeEvaluateReceiptRules(receipt, false),
    ...(trust.keyTrusted === undefined ? {} : { keyTrusted: trust.keyTrusted }),
  };
};

const hostileReceiptResult = (
  receipt: unknown,
  opts: VerifyReceiptOptions,
): VerifyReceiptResult => {
  const trust = resolveShapeFailureTrust(receipt, opts);
  return {
    valid: false,
    stale: false,
    reasons:
      trust.reason === undefined
        ? ["shape_not_an_object"]
        : ["shape_not_an_object", trust.reason],
    ...malformedRulesResult(),
    ...(trust.keyTrusted === undefined ? {} : { keyTrusted: trust.keyTrusted }),
  };
};

const isStringArray = (v: unknown): v is string[] =>
  Array.isArray(v) && v.every((x) => typeof x === "string");

const isFindingArray = (v: unknown): boolean =>
  Array.isArray(v) &&
  v.every(
    (f) =>
      f !== null &&
      typeof f === "object" &&
      typeof (f as Record<string, unknown>).code === "string" &&
      typeof (f as Record<string, unknown>).source === "string",
  );

const isInterpretationArray = (v: unknown): boolean =>
  Array.isArray(v) &&
  v.every(
    (i) =>
      i !== null &&
      typeof i === "object" &&
      typeof (i as Record<string, unknown>).code === "string" &&
      typeof (i as Record<string, unknown>).text === "string" &&
      typeof (i as Record<string, unknown>).lang === "string",
  );

// Step 1 (SPEC §8): exact §4 field set with correct types. Returns shape problems.
const checkShape = (receipt: Record<string, unknown>): string[] => {
  const reasons: string[] = [];
  const keys = Object.keys(receipt);
  const expected = new Set<string>(RECEIPT_FIELDS);
  for (const k of keys) {
    if (!expected.has(k)) reasons.push(`shape_unexpected_field:${k}`);
  }
  for (const f of RECEIPT_FIELDS) {
    if (!(f in receipt)) reasons.push(`shape_missing_field:${f}`);
  }
  if (reasons.length > 0) return reasons;

  const r = receipt;
  const str = (k: string): void => {
    if (typeof r[k] !== "string") reasons.push(`shape_type:${k}`);
  };
  str("chain");
  str("mintAddress");
  str("tokenProgramAddress");
  if (!Number.isSafeInteger(r.slot)) reasons.push("shape_type:slot");
  str("timestamp");
  str("rulesVersion");
  str("findingTaxonomyVersion");
  if (!isStringArray(r.scopeChecksPerformed)) reasons.push("shape_type:scopeChecksPerformed");
  if (!isStringArray(r.scopeChecksNotPerformed)) reasons.push("shape_type:scopeChecksNotPerformed");
  if (!isStringArray(r.coverageGaps)) reasons.push("shape_type:coverageGaps");
  if (!isFindingArray(r.findings)) reasons.push("shape_type:findings");
  if (!isInterpretationArray(r.interpretations)) reasons.push("shape_type:interpretations");
  if (!Number.isSafeInteger(r.maxAgeSeconds)) reasons.push("shape_type:maxAgeSeconds");
  str("disclaimer");
  str("payloadHash");
  str("receiptId");
  str("signature");
  str("signerPublicKey");
  return reasons;
};

/** Extract the 14 signed-preimage body fields from a full receipt. */
const extractBody = (receipt: Record<string, unknown>): ReceiptV1Body => {
  const body = {} as Record<string, unknown>;
  for (const f of RECEIPT_BODY_FIELDS) body[f] = receipt[f];
  return body as unknown as ReceiptV1Body;
};

const recomputePayloadHash = (body: ReceiptV1Body): string =>
  "sha256:" + createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");

const toIso = (now: string | Date | undefined): string =>
  now === undefined ? new Date().toISOString() : typeof now === "string" ? now : now.toISOString();

/**
 * Verify a receipt v1 (SPEC §8). All of steps 1–5 must hold for `valid: true`.
 * Step 6 (key trust) and step 7 (freshness) are reported but NON-FATAL.
 *
 * Reasons are accumulated (not short-circuited) so a tampered receipt surfaces
 * every failed check — e.g. an altered disclaimer reports both the disclaimer
 * mismatch and the resulting payload-hash mismatch.
 */
const verifyReceiptV1Internal = (
  receipt: unknown,
  opts: VerifyReceiptOptions = {},
): VerifyReceiptResult => {
  const reasons: string[] = [];

  if (!isInspectableObject(receipt)) {
    // The trust axis is reported even here: it must not depend on receipt
    // validity. Additive and non-fatal — `valid` is already false on the SHAPE
    // reason alone, and the trust reason is appended after it.
    return shapeNotObjectResult(receipt, opts);
  }
  const r = receipt as Record<string, unknown>;

  // 1. Shape. If the shape is wrong we cannot trust any other check.
  const shapeReasons = checkShape(r);
  if (shapeReasons.length > 0) {
    const trust = resolveShapeFailureTrust(r, opts);
    return {
      valid: false,
      stale: false,
      reasons: trust.reason === undefined ? shapeReasons : [...shapeReasons, trust.reason],
      ...safeEvaluateReceiptRules(r, false),
      ...(trust.keyTrusted === undefined ? {} : { keyTrusted: trust.keyTrusted }),
    };
  }

  // 2. Disclaimer byte-for-byte (SPEC §5).
  if (r.disclaimer !== RECEIPT_DISCLAIMER) reasons.push("disclaimer_mismatch");

  // 3+4. Forbidden words (SPEC §6) + payload hash. Both walks recurse through
  // attacker-shaped structures (findings[].evidence may nest arbitrarily), so
  // any failure there — e.g. stack exhaustion from hostile nesting — is
  // CONTAINED as an invalid-receipt reason. Hostile input must produce an
  // outcome, never an exception.
  const body = extractBody(r);
  let recomputed: string | null = null;
  try {
    const forbidden = findForbiddenWords(collectStrings(body));
    for (const w of forbidden) reasons.push(`forbidden_word:${w}`);
    recomputed = recomputePayloadHash(body);
  } catch {
    reasons.push("canonicalization_failed");
  }
  if (recomputed !== null && recomputed !== r.payloadHash) {
    reasons.push("payload_hash_mismatch");
  }

  // 4b. receiptId = "raven-receipt-v1:" + payloadHash.
  if (r.receiptId !== RECEIPT_ID_PREFIX + (r.payloadHash as string)) {
    reasons.push("receipt_id_mismatch");
  }

  // 5. Signature over the domain-separated envelope (SPEC §3/§8).
  const signedBytes = canonicalJson({
    domain: RECEIPT_DOMAIN,
    version: RECEIPT_VERSION,
    payloadHash: r.payloadHash,
  });
  // Property-access failure is a hostile live object, not a cryptographic
  // failure. Capture both top-level values before the crypto-only catch and
  // reuse the signer for the later trust axis.
  const signatureValue = r.signature as string;
  const signerPublicKey = r.signerPublicKey as string;
  let signatureOk = false;
  try {
    const signerPublicKeyBytes = decodeCanonicalEd25519Spki(signerPublicKey);
    let pub = publicKeyCache.get(signerPublicKey);
    if (!pub) {
      pub = createPublicKey({
        key: signerPublicKeyBytes,
        format: "der",
        type: "spki",
      });
      // The receipt-v1 signature algorithm is Ed25519 (SPEC §3). Building a
      // key from an untrusted SPKI and calling cryptoVerify(null, …) lets the
      // key choose the algorithm, so an attacker-chosen RSA/EC key verifies
      // (ledgered divergence D3). Reject non-Ed25519 keys exactly like the
      // Python reference verifier ("not an Ed25519 SPKI key").
      if (pub.asymmetricKeyType !== "ed25519") {
        throw new Error("not an Ed25519 SPKI key");
      }
      cachePublicKey(signerPublicKey, pub);
    }
    signatureOk = cryptoVerify(
      null,
      Buffer.from(signedBytes, "utf8"),
      pub,
      decodeCanonicalBase64(signatureValue),
    );
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) reasons.push("signature_invalid");

  // valid is gated ONLY by steps 1–5.
  const valid = reasons.length === 0;
  const rules = evaluateReceiptRules(r, valid);

  // 6. Key trust (optional, NON-FATAL). Reported separately from `valid`.
  const trust = resolveKeyTrust(signerPublicKey, opts);
  const keyTrusted = trust.keyTrusted;
  if (trust.reason !== undefined) reasons.push(trust.reason);

  // 7. Freshness (reported, NON-FATAL — SPEC §7). Staleness ≠ tampered. An
  // unparseable timestamp makes freshness UNPROVABLE — fail closed and report
  // stale with a dedicated reason, never fresh-forever.
  const ageSeconds =
    (Date.parse(toIso(opts.now)) - Date.parse(r.timestamp as string)) / 1000;
  let stale: boolean;
  if (Number.isFinite(ageSeconds)) {
    stale = ageSeconds > (r.maxAgeSeconds as number);
    if (stale) reasons.push("stale");
  } else {
    stale = true;
    reasons.push("timestamp_unparseable");
  }

  return {
    valid,
    stale,
    reasons,
    ...rules,
    ...(keyTrusted === undefined ? {} : { keyTrusted }),
  };
};

/**
 * Total customer boundary for live JavaScript values. A receipt accessor or
 * Proxy trap may throw at any read, including after shape inspection; callers
 * receive the closed hostile-object outcome and continue executing.
 */
export const verifyReceiptV1 = (
  receipt: unknown,
  opts: VerifyReceiptOptions = {},
): VerifyReceiptResult => {
  try {
    return verifyReceiptV1Internal(receipt, opts);
  } catch {
    try {
      return hostileReceiptResult(receipt, opts);
    } catch {
      return {
        valid: false,
        stale: false,
        reasons: ["shape_not_an_object"],
        ...malformedRulesResult(),
      };
    }
  }
};
