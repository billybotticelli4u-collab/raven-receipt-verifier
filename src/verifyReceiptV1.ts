// Raven Receipt v1 — open verification library (SPEC §8).
//
// Byte-for-byte port of `apps/launchguard-acp/src/receipt/verifyReceiptV1.ts`, with
// imports rewired to this package's local canonicalJson + constants. It depends on
// NOTHING proprietary and NOTHING networked: only `node:crypto`. The closed signer
// GENERATES receipts; this library VERIFIES them.
//
// Result contract (matches the production verifier):
//   { valid, stale, reasons, rulesVersion, rulesStatus, rulesReasons, keyTrusted }
// `valid` is gated ONLY by checks 1–5 (shape, disclaimer, forbidden words, payload
// hash + receiptId, signature). Key trust (6) and freshness (7) are reported but
// NON-FATAL — a self-consistent signature from an untrusted key is still a valid
// signature, and a stale receipt is still an authentic one. Rules conformance is
// a third independent axis and never changes those historical fields.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";
import {
  assertEd25519SpkiDerKeyDomain,
  assertEd25519SignatureDomain,
  ED25519_KEY_DOMAIN_SEMANTICS,
} from "./ed25519KeyDomain.ts";
export { ED25519_KEY_DOMAIN_SEMANTICS };

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

export const decodeCanonicalBase64 = (value: string): Buffer => {
  if (!CANONICAL_BASE64.test(value)) throw new Error("noncanonical base64");
  const decoded = Buffer.from(value, "base64");
  if (decoded.toString("base64") !== value) throw new Error("noncanonical base64");
  return decoded;
};

export const decodeCanonicalEd25519Spki = (value: string): Buffer => {
  const decoded = decodeCanonicalBase64(value);
  if (
    decoded.length !== ED25519_SPKI_PREFIX.length + 32 ||
    !decoded.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    throw new Error("not a canonical Ed25519 SPKI key");
  }
  // libsodium crypto_sign_verify_detached key-domain: canonicalize + reject small-order
  // before any backend crypto.verify call (and at trust-config load via classifyTrustKey).
  assertEd25519SpkiDerKeyDomain(decoded);
  return decoded;
};

type TrustKeyEligibility = "supported" | "unsupported" | "invalid";

const readDerLength = (der: Buffer, offset: number): { length: number; next: number } => {
  if (offset >= der.length) throw new Error("missing DER length");
  const first = der[offset];
  if (first < 0x80) return { length: first, next: offset + 1 };
  const octets = first & 0x7f;
  if (octets === 0 || octets > 4 || offset + 1 + octets > der.length) {
    throw new Error("invalid DER length");
  }
  if (der[offset + 1] === 0) throw new Error("non-minimal DER length");
  let length = 0;
  for (let i = 0; i < octets; i++) length = length * 256 + der[offset + 1 + i];
  if (length < 0x80) throw new Error("non-minimal DER length");
  return { length, next: offset + 1 + octets };
};

const readDerElement = (
  der: Buffer,
  offset: number,
  tag: number,
): { contentStart: number; end: number } => {
  if (offset >= der.length || der[offset] !== tag) throw new Error("unexpected DER tag");
  const { length, next } = readDerLength(der, offset + 1);
  const end = next + length;
  if (end > der.length) throw new Error("truncated DER element");
  return { contentStart: next, end };
};

const isCanonicalDerOid = (der: Buffer, start: number, end: number): boolean => {
  if (start === end) return false;
  let offset = start;
  while (offset < end) {
    if (der[offset] === 0x80) return false;
    do {
      if (offset >= end) return false;
    } while ((der[offset++] & 0x80) !== 0);
  }
  return true;
};

/** Classify canonical receipt-v1 trust material without invoking crypto. */
const classifyTrustKey = (value: string): TrustKeyEligibility => {
  let der: Buffer | undefined;
  try {
    der = decodeCanonicalBase64(value);
  } catch {
    return "invalid";
  }
  // Exact Ed25519 SPKI prefix: apply libsodium key-domain (canonicalize + small-order).
  // Failures here are invalid trust material, not "unsupported algorithm".
  if (
    der.length === ED25519_SPKI_PREFIX.length + 32 &&
    der.subarray(0, ED25519_SPKI_PREFIX.length).equals(ED25519_SPKI_PREFIX)
  ) {
    try {
      decodeCanonicalEd25519Spki(value);
      return "supported";
    } catch {
      return "invalid";
    }
  }
  try {
    const outer = readDerElement(der, 0, 0x30);
    if (outer.end !== der.length) throw new Error("trailing DER data");
    const algorithm = readDerElement(der, outer.contentStart, 0x30);
    const oid = readDerElement(der, algorithm.contentStart, 0x06);
    if (oid.end > algorithm.end || !isCanonicalDerOid(der, oid.contentStart, oid.end)) {
      throw new Error("invalid algorithm OID");
    }
    if (oid.end < algorithm.end) {
      const parameter = readDerElement(der, oid.end, der[oid.end]);
      if (parameter.end !== algorithm.end) throw new Error("extra algorithm parameters");
    }
    const keyBits = readDerElement(der, algorithm.end, 0x03);
    if (keyBits.end !== outer.end || keyBits.contentStart === keyBits.end) {
      throw new Error("invalid SPKI key bits");
    }
    const unusedBits = der[keyBits.contentStart];
    if (unusedBits > 7 || keyBits.contentStart + 1 === keyBits.end) {
      throw new Error("invalid SPKI bit string");
    }
    if (unusedBits > 0 && (der[keyBits.end - 1] & ((1 << unusedBits) - 1)) !== 0) {
      throw new Error("nonzero DER padding bits");
    }
    return "unsupported";
  } catch {
    return "invalid";
  }
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
   * hold. Key trust is always reported via `keyTrusted`. Trust is
   * NON-FATAL — it never gates `valid`.
   *
   * Every malformed value fails closed and typed: a malformed collection,
   * non-Ed25519 pin-set member, or key encoding yields `trust_config_invalid`.
   * A non-Ed25519 signer yields `trust_key_type_unsupported` (never
   * `keyTrusted:true` by match). Only canonical Ed25519 SPKI is eligible to
   * establish receipt-v1 trust (Owner 1A).
   */
  trustedKeys?: ReadonlySet<string> | readonly string[] | null;
  /**
   * Typed relationship to trust evaluation when no `trustedKeys` are
   * supplied: `true` opts out deliberately (`key_trust_not_evaluated`);
   * `false` declares untrusted keys unacceptable — with no keys supplied that
   * is a contract error on the trust axis (`trust_config_invalid`), never a
   * silent pass. When both options are omitted, trust configuration is missing
   * and fails closed on the trust axis (`keyTrusted: false` with
   * `trust_config_missing`), never as an absent axis. Non-object whole options
   * (null, array, primitive) are `trust_config_invalid` (Owner 2A).
   */
  allowUntrustedKey?: boolean;
}

/**
 * Normalize a caller-supplied trustedKeys collection to a Set of strings.
 * Returns null on ANY malformed collection shape. Key encodings are classified
 * separately so a syntactically valid unsupported SPKI remains distinguishable
 * from malformed trust material.
 */
const isExactArray = (value: unknown): value is readonly string[] =>
  Array.isArray(value) && Object.getPrototypeOf(value) === Array.prototype;

const isExactSet = (value: unknown): value is ReadonlySet<string> =>
  typeof value === "object" &&
  value !== null &&
  Object.getPrototypeOf(value) === Set.prototype;

export const normalizeTrustedKeys = (
  input: ReadonlySet<string> | readonly string[] | null | undefined,
): ReadonlySet<string> | null => {
  // Exception containment: a hostile collection (a revoked Proxy, a Set
  // subclass whose iterator throws, a throwing getter) must degrade to the
  // typed malformed outcome — no exception escapes for any input value.
  // Exact built-in Array/Set only (Owner 4A): subclasses match Python
  // `type() is list/set` rejection and cannot override hooks.
  try {
    let entries: unknown;
    if (isExactSet(input)) {
      entries = [...input];
    } else if (isExactArray(input)) {
      entries = input;
    } else {
      return null;
    }
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
 * Copy recognized option fields onto a fresh plain object before verifier work
 * begins. This is a security boundary: hostile whole-options objects and
 * throwing/stateful accessors must not escape into receipt-shape containment or
 * be read more than once on the trust axis.
 */
export type SanitizedVerifyOptions = VerifyReceiptOptions & {
  /** Whole-options was a non-object (null, array, primitive). Owner 2A. */
  wholeOptionsInvalid?: true;
};

// Own-property discipline (Phase-B blocker 1, 2026-09-05): only OWN properties
// the caller supplied define verifier options. Inherited properties — whether
// from Object.prototype pollution or a hostile custom prototype — are
// semantically ABSENT and their getters are never invoked. hasOwnProperty is
// captured at module load so it cannot itself be swapped on the prototype.
const hasOwnProperty = Object.prototype.hasOwnProperty;
const hasOwn = (target: object, key: string): boolean => hasOwnProperty.call(target, key);
// Hostility probe: reading a module-private Symbol can meet no accessor on any
// honest object's prototype chain (nothing else holds the symbol), so it never
// invokes an inherited getter; an options Proxy whose `get` trap throws on every
// read is still detected and fails typed (Owner 3A), exactly as before.
const HOSTILITY_PROBE: unique symbol = Symbol("raven.verify.options-probe");

export const sanitizeOptions = (options: unknown): SanitizedVerifyOptions => {
  // Null prototype: the snapshot itself must not inherit anything either.
  const out = Object.create(null) as SanitizedVerifyOptions;
  // Owner 2A: only undefined/omitted is missing; any other non-object is invalid.
  if (options === undefined) return out;
  try {
    if (options === null || typeof options !== "object" || Array.isArray(options)) {
      out.wholeOptionsInvalid = true;
      return out;
    }
    // Re-entry: already-sanitized invalid snapshot must not be re-read as omission.
    if (hasOwn(options, "wholeOptionsInvalid") &&
        (options as { wholeOptionsInvalid?: unknown }).wholeOptionsInvalid) {
      out.wholeOptionsInvalid = true;
      return out;
    }
  } catch {
    // Revoked Proxy / hostile IsArray traps → malformed trust config (Owner 3A).
    out.wholeOptionsInvalid = true;
    return out;
  }

  let trustAccessorFailed = false;
  try {
    void (options as Record<symbol, unknown>)[HOSTILITY_PROBE];
  } catch {
    trustAccessorFailed = true;
  }
  try {
    if (hasOwn(options, "now")) {
      const now = (options as VerifyReceiptOptions).now;
      if (now !== undefined) out.now = now;
    }
  } catch {
    // Drop `now`: freshness falls back to real time.
  }
  try {
    if (hasOwn(options, "trustedKeys")) {
      const trustedKeys = (options as VerifyReceiptOptions).trustedKeys;
      if (trustedKeys !== undefined) out.trustedKeys = trustedKeys;
    }
  } catch {
    trustAccessorFailed = true;
  }
  try {
    if (hasOwn(options, "allowUntrustedKey")) {
      const allowUntrustedKey = (options as VerifyReceiptOptions).allowUntrustedKey;
      if (allowUntrustedKey !== undefined) out.allowUntrustedKey = allowUntrustedKey;
    }
  } catch {
    trustAccessorFailed = true;
  }

  if (trustAccessorFailed) {
    delete out.trustedKeys;
    // Force typed malformed trust config (Owner 3A): never blame the receipt.
    out.allowUntrustedKey = false;
  }
  return out;
};

/**
 * Resolve the key-trust axis (check 6, NON-FATAL). Shared by the Solana and
 * EVM verifiers so both enforce the same trust-input contract.
 */
export const resolveKeyTrust = (
  signerPublicKey: string,
  rawOpts:
    | Pick<VerifyReceiptOptions, "trustedKeys" | "allowUntrustedKey">
    | SanitizedVerifyOptions,
): { keyTrusted: boolean; reason?: string } => {
  // Always re-snapshot own properties: a raw caller object is captured
  // own-property-only; an existing snapshot (null prototype, plain data)
  // re-copies unchanged. No prototype-walking `in` test decides the path.
  const opts: SanitizedVerifyOptions = sanitizeOptions(rawOpts);
  // Owner 2A: non-object whole options are malformed, not omission.
  if (opts.wholeOptionsInvalid) {
    return { keyTrusted: false, reason: "trust_config_invalid" };
  }
  // A supplied allowUntrustedKey that is not a boolean (realistic for
  // env-derived strings such as "false") is malformed trust configuration:
  // fail closed and typed, never silently treat it as omitted. This check
  // runs before the trustedKeys path so a malformed flag is invalid even
  // when valid keys are supplied.
  if (opts.allowUntrustedKey !== undefined && typeof opts.allowUntrustedKey !== "boolean") {
    return { keyTrusted: false, reason: "trust_config_invalid" };
  }
  // R7/R9: supplying trustedKeys together with allowUntrustedKey:true is a
  // contradiction — refuse rather than silently preferring either side.
  if (opts.trustedKeys !== undefined && opts.allowUntrustedKey === true) {
    return { keyTrusted: false, reason: "trust_config_invalid" };
  }
  if (opts.trustedKeys !== undefined) {
    const keys = normalizeTrustedKeys(opts.trustedKeys);
    if (keys === null) return { keyTrusted: false, reason: "trust_config_invalid" };
    for (const key of keys) {
      const eligibility = classifyTrustKey(key);
      // Owner 1A: non-Ed25519 member in the pin set is malformed config.
      if (eligibility === "invalid" || eligibility === "unsupported") {
        return { keyTrusted: false, reason: "trust_config_invalid" };
      }
    }
    // Owner 1A: non-Ed25519 signer → trust_key_type_unsupported; never true
    // by match. Precedence: after trust_config_invalid, before key_untrusted.
    if (signerPublicKey) {
      const signerEligibility = classifyTrustKey(signerPublicKey);
      if (signerEligibility === "unsupported") {
        return { keyTrusted: false, reason: "trust_key_type_unsupported" };
      }
    }
    const keyTrusted = keys.has(signerPublicKey);
    return keyTrusted ? { keyTrusted: true } : { keyTrusted: false, reason: "key_untrusted" };
  }
  if (opts.allowUntrustedKey === true) {
    return { keyTrusted: false, reason: "key_trust_not_evaluated" };
  }
  if (opts.allowUntrustedKey === false) {
    return { keyTrusted: false, reason: "trust_config_invalid" };
  }
  // Owner 2A / R1: omission of trust policy fields → trust_config_missing.
  return { keyTrusted: false, reason: "trust_config_missing" };
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
 * Trust is a separate NON-FATAL axis, so it is reported on every result —
 * `keyTrusted` must never disappear just because receipt shape failed. The main
 * path already resolves trust after a FAILED signature check; a shape failure
 * must not report less.
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
): { keyTrusted: boolean; reason?: string } => {
  const signerPublicKey = readSignerPublicKey(receipt);
  // An absent signer is represented by "". Since every eligible trust key is
  // a canonical Ed25519 SPKI, that placeholder cannot match an accepted key.
  return resolveKeyTrust(signerPublicKey ?? "", opts);
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
  /** Signer trust axis. False means untrusted, unevaluated by explicit opt-out, or malformed/missing trust config. */
  keyTrusted: boolean;
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
    keyTrusted: trust.keyTrusted,
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
    keyTrusted: trust.keyTrusted,
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

/**
 * Failures raised while converting the CALLER's `now` option, tagged so the
 * hostile-receipt boundary rethrows them unchanged instead of reporting them as
 * a receipt failure. Recognition is closure-private identity: a WeakMap lookup
 * cannot be forged by an attacker-thrown value, and it never runs attacker code
 * — unlike `instanceof`, which would hand `[[GetPrototypeOf]]` to a revoked
 * Proxy and escape the boundary it is meant to hold.
 */
const dateOptionFailures = new WeakMap<object, { readonly thrown: unknown }>();

const toIso = (now: string | Date | undefined): string => {
  if (now === undefined) return new Date().toISOString();
  if (typeof now === "string") return now;
  try {
    return now.toISOString();
  } catch (thrown) {
    const marker = new Error("raven-verify: date option conversion failed");
    dateOptionFailures.set(marker, { thrown });
    throw marker;
  }
};

/** Rethrow the caller's own option failure, exactly as it was thrown. */
const rethrowDateOptionFailure = (failure: unknown): void => {
  if (failure === null || typeof failure !== "object") return;
  const tagged = dateOptionFailures.get(failure);
  if (tagged !== undefined) throw tagged.thrown;
};

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
      keyTrusted: trust.keyTrusted,
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
    const signatureBytes = decodeCanonicalBase64(signatureValue);
    assertEd25519SignatureDomain(signatureBytes);
    signatureOk = cryptoVerify(
      null,
      Buffer.from(signedBytes, "utf8"),
      pub,
      signatureBytes,
    );
  } catch {
    signatureOk = false;
  }
  if (!signatureOk) reasons.push("signature_invalid");

  // valid is gated ONLY by steps 1–5.
  const valid = reasons.length === 0;
  const rules = evaluateReceiptRules(r, valid);

  // 6. Key trust (NON-FATAL). Reported separately from `valid`.
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
    keyTrusted,
  };
};

/**
 * Total customer boundary for live JavaScript values. A receipt accessor or
 * Proxy trap may throw at any read, including after shape inspection; callers
 * receive the closed hostile-object outcome and continue executing.
 */
export const verifyReceiptV1 = (
  receipt: unknown,
  opts?: VerifyReceiptOptions,
): VerifyReceiptResult => {
  const safeOpts = sanitizeOptions(opts);
  try {
    return verifyReceiptV1Internal(receipt, safeOpts);
  } catch (failure) {
    // A caller's own option failure is not a receipt outcome: it keeps the
    // exception the caller would have seen before this boundary existed.
    rethrowDateOptionFailure(failure);
    try {
      return hostileReceiptResult(receipt, safeOpts);
    } catch {
      return {
        valid: false,
        stale: false,
        reasons: ["shape_not_an_object", "trust_config_invalid"],
        ...malformedRulesResult(),
        keyTrusted: false,
      };
    }
  }
};
