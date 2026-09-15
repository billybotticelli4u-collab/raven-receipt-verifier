// Exact, offline rules-version dispatch for Solana raven-receipt/v1.
//
// Receipt integrity and rules conformance are deliberately separate axes. This
// module runs only after receipt-v1 integrity succeeds. Historical identities
// retain their recorded meaning; only raven-rules@1.1.4 receives the holder
// provenance checks frozen for Sprint 1A.

import { canonicalJson } from "./canonicalJson.ts";

export type RulesStatus =
  | "supported_valid"
  | "supported_invalid"
  | "unsupported"
  | "malformed"
  | null;

export interface ReceiptRulesResult {
  rulesVersion: string | null;
  rulesStatus: RulesStatus;
  rulesReasons: string[];
}

const HISTORICAL_RULES = new Set([
  "raven-rules@1.0.0",
  "raven-rules@1.1.0",
  "raven-rules@1.1.1",
  "raven-rules@1.1.2",
  "raven-rules@1.1.3",
]);
const RULES_1_1_4 = "raven-rules@1.1.4";
const CANONICAL_RULES_VERSION = /^raven-rules@[0-9]+\.[0-9]+\.[0-9]+$/;

const HOLDER_PRIMARY = new Set([
  "holders.concentration_high",
  "holders.concentration_moderate",
  "holders.distributed",
  "holders.distribution_unresolved",
]);
const HOLDER_AFFIRMATIVE = new Set([
  "holders.concentration_high",
  "holders.concentration_moderate",
  "holders.distributed",
]);
const HOLDER_QUALIFIERS = new Set([
  "holders.adjusted_for_known_venues",
  "holders.unadjusted_may_include_pools",
]);
const HOLDER_VENUE = new Set([
  "venue.pumpfun_curve_active",
  "venue.pumpfun_curve_complete",
]);
const HOLDER_DERIVED = new Set([
  ...HOLDER_PRIMARY,
  ...HOLDER_QUALIFIERS,
  ...HOLDER_VENUE,
]);
const LIQUIDITY_FINDINGS = new Set([
  "venue.liquidity_locked",
  "venue.liquidity_partially_locked",
  "venue.liquidity_withdrawable",
  "venue.liquidity_unresolved",
  "liquidity.curve_active_protocol_custody",
  "liquidity.pumpswap_canonical_pool_present",
  "liquidity.supply_majority_returned_to_pool",
]);
const ATTEMPTED_CHECKS = [
  "largest_accounts",
  "token_supply",
  "venue_custody",
  "liquidity_coherence",
] as const;
const PRE_OBSERVATION_REASONS = new Set([
  "holder_fetch_failed",
  "holder_decode_failed",
  "supply_fetch_failed",
  "holder_observation_slot_missing",
  "holder_observation_slot_mismatch",
]);
const COHERENT_UNAVAILABLE_REASONS = new Set([
  "zero_total_supply",
  "no_holder_accounts_returned",
  "holder_amounts_exceed_supply",
  "all_accounts_excluded",
]);
const UNAVAILABLE_REASONS = new Set([
  ...PRE_OBSERVATION_REASONS,
  ...COHERENT_UNAVAILABLE_REASONS,
]);
const RULES_REASON_ORDER = [
  "producer_context_invalid",
  "holder_attempt_not_executed",
  "holder_attempt_not_completed",
  "holder_not_selected_but_present",
  "holder_attempt_unexpected",
  "finding_codes_mismatch",
  "holder_finding_shape_invalid",
  "holder_finding_source_invalid",
  "holder_finding_subject_invalid",
  "holder_finding_evidence_invalid",
  "holder_primary_cardinality_invalid",
  "holder_state_contradiction",
  "holder_qualifier_cardinality_invalid",
  "holder_venue_state_contradiction",
  "holder_attempt_missing",
  "holder_attempt_shape_invalid",
  "holder_attempt_version_invalid",
  "holder_attempt_state_invalid",
  "holder_attempt_source_invalid",
  "holder_attempt_result_invalid",
  "holder_attempt_reason_invalid",
  "holder_attempt_mint_mismatch",
  "holder_attempt_commitment_mismatch",
  "holder_attempt_checks_invalid",
  "holder_attempt_observation_invalid",
  "holder_attempt_copy_mismatch",
  "holder_attempt_expectation_mismatch",
  "holder_classifier_expectation_mismatch",
  "holder_observation_slot_mismatch",
  "holder_metadata_context_mismatch",
  "holder_liquidity_context_mismatch",
  "holder_venue_context_mismatch",
  "holder_coverage_gap_invalid",
  "holder_scope_checks_invalid",
] as const;

type JsonObject = Record<string, unknown>;
type HolderState = "not_requested" | "attempted_unavailable" | "observed";

/**
 * True for a plain, inspectable object. Total: never throws for any input. A
 * revoked Proxy makes `Array.isArray` itself raise a TypeError, so an unguarded
 * check escapes the verifier entirely instead of yielding the ordinary
 * malformed-receipt outcome (ported from the ACP surface, #93).
 */
export const isInspectableObject = (value: unknown): boolean => {
  if (value === null || typeof value !== "object") return false;
  try {
    return !Array.isArray(value);
  } catch {
    return false;
  }
};

const isObject = (value: unknown): value is JsonObject => isInspectableObject(value);

const hasExactKeys = (value: unknown, keys: readonly string[]): value is JsonObject => {
  if (!isObject(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  return actual.length === expected.length && actual.every((key, i) => key === expected[i]);
};

const isStringArray = (value: unknown): value is string[] =>
  Array.isArray(value) && value.every((entry) => typeof entry === "string");

const has = (value: unknown, member: string): boolean =>
  isStringArray(value) && value.includes(member);

const isPositiveSafeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) > 0;

const isNonnegativeSafeInteger = (value: unknown): value is number =>
  Number.isSafeInteger(value) && (value as number) >= 0;

const isDigits = (value: unknown): value is string =>
  typeof value === "string" && /^[0-9]+$/.test(value);

const isPositiveDigits = (value: unknown): value is string =>
  typeof value === "string" && /^[1-9][0-9]*$/.test(value);

const isUniqueStringArray = (value: unknown): value is string[] =>
  isStringArray(value) && new Set(value).size === value.length;

const isNonemptyString = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0;

const isSolanaAddress = (value: unknown): value is string => {
  if (typeof value !== "string" || value.length < 32 || value.length > 44) return false;
  const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  let decoded = 0n;
  for (const char of value) {
    const digit = alphabet.indexOf(char);
    if (digit < 0) return false;
    decoded = decoded * 58n + BigInt(digit);
  }
  let nonzeroBytes = 0;
  for (let n = decoded; n > 0n; n >>= 8n) nonzeroBytes += 1;
  let leadingZeroBytes = 0;
  while (leadingZeroBytes < value.length && value[leadingZeroBytes] === "1") {
    leadingZeroBytes += 1;
  }
  return leadingZeroBytes + nonzeroBytes === 32;
};

const canonicalEqual = (left: unknown, right: unknown): boolean => {
  try {
    return canonicalJson(left) === canonicalJson(right);
  } catch {
    return false;
  }
};

const isHolderAttemptSymbol = (key: PropertyKey): boolean =>
  typeof key === "symbol" && key.description === "holderAttempt";

const hasInheritedHolderAttempt = (value: object): boolean => {
  let prototype: object | null;
  try {
    prototype = Object.getPrototypeOf(value);
  } catch {
    return true;
  }
  while (prototype !== null) {
    try {
      if (Object.getOwnPropertyDescriptor(prototype, "holderAttempt")) return true;
      if (Object.getOwnPropertySymbols(prototype).some(isHolderAttemptSymbol)) return true;
      prototype = Object.getPrototypeOf(prototype);
    } catch {
      return true;
    }
  }
  return false;
};

/**
 * `holderAttempt` is only meaningful as the direct data member of the evidence
 * object on a recognized holder-derived finding. Inspect descriptors rather than
 * reading attacker-controlled properties so a getter/proxy cannot hide or alter
 * the semantic graph while rules are evaluated.
 */
const containsUnexpectedHolderAttempt = (
  value: unknown,
  canonicalHolderEvidence = false,
  seen = new WeakSet<object>(),
): boolean => {
  if (value === null || typeof value !== "object") return false;
  if (seen.has(value)) return false;
  seen.add(value);
  if (hasInheritedHolderAttempt(value)) return true;

  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(value);
  } catch {
    return true;
  }
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(value, key);
    } catch {
      return true;
    }
    if (!descriptor) return true;
    if (isHolderAttemptSymbol(key)) return true;
    if (key === "holderAttempt") {
      if (
        !canonicalHolderEvidence ||
        !("value" in descriptor) ||
        descriptor.get !== undefined ||
        descriptor.set !== undefined
      ) {
        return true;
      }
      if (containsUnexpectedHolderAttempt(descriptor.value, false, seen)) return true;
      continue;
    }
    if ("value" in descriptor && containsUnexpectedHolderAttempt(descriptor.value, false, seen)) {
      return true;
    }
  }
  return false;
};

const findingHasUnexpectedHolderAttempt = (
  finding: JsonObject,
  isHolderDerived: boolean,
): boolean => {
  if (!isHolderDerived) return containsUnexpectedHolderAttempt(finding);
  if (hasInheritedHolderAttempt(finding)) return true;

  let keys: PropertyKey[];
  try {
    keys = Reflect.ownKeys(finding);
  } catch {
    return true;
  }
  for (const key of keys) {
    let descriptor: PropertyDescriptor | undefined;
    try {
      descriptor = Object.getOwnPropertyDescriptor(finding, key);
    } catch {
      return true;
    }
    if (!descriptor) return true;
    if (key === "holderAttempt" || isHolderAttemptSymbol(key)) return true;
    if (key === "evidence") {
      if (!("value" in descriptor) || descriptor.get !== undefined || descriptor.set !== undefined) {
        return true;
      }
      if (containsUnexpectedHolderAttempt(descriptor.value, true)) return true;
    } else if ("value" in descriptor && containsUnexpectedHolderAttempt(descriptor.value)) {
      return true;
    }
  }
  return false;
};

const isCanonicalAttemptedChecks = (value: unknown): value is string[] => {
  if (!isStringArray(value) || value.length === 0 || value[0] !== "largest_accounts") {
    return false;
  }
  let last = -1;
  for (const check of value) {
    const index = ATTEMPTED_CHECKS.indexOf(check as (typeof ATTEMPTED_CHECKS)[number]);
    if (index <= last) return false;
    last = index;
  }
  return true;
};

const exactChecks = (actual: unknown, required: readonly string[], optional: readonly string[] = []): boolean => {
  if (!isCanonicalAttemptedChecks(actual)) return false;
  for (const check of required) if (!actual.includes(check)) return false;
  for (const check of actual) if (!required.includes(check) && !optional.includes(check)) return false;
  return true;
};

const metricBase = (value: JsonObject): boolean =>
  value.basis === "total_supply" && isDigits(value.supplyRaw);

const digitBigInt = (value: unknown): bigint | null =>
  isDigits(value) ? BigInt(value) : null;

const checkUnavailableMetrics = (reason: unknown, metrics: unknown): boolean => {
  if (reason === "zero_total_supply" || reason === "no_holder_accounts_returned") {
    if (!hasExactKeys(metrics, ["basis", "supplyRaw"]) || !metricBase(metrics)) return false;
    const supply = digitBigInt(metrics.supplyRaw);
    return reason === "zero_total_supply" ? supply === 0n : supply !== null && supply > 0n;
  }
  if (reason === "holder_amounts_exceed_supply") {
    return (
      hasExactKeys(metrics, ["basis", "supplyRaw", "accountsConsidered"]) &&
      metricBase(metrics) &&
      (digitBigInt(metrics.supplyRaw) ?? 0n) > 0n &&
      isPositiveSafeInteger(metrics.accountsConsidered)
    );
  }
  if (reason === "all_accounts_excluded") {
    if (
      !hasExactKeys(metrics, ["basis", "supplyRaw", "excludedCount", "excludedAmountRaw"]) ||
      !metricBase(metrics) ||
      !isPositiveSafeInteger(metrics.excludedCount) ||
      !isDigits(metrics.excludedAmountRaw)
    ) return false;
    const supply = digitBigInt(metrics.supplyRaw);
    const excluded = digitBigInt(metrics.excludedAmountRaw);
    return supply !== null && supply > 0n && excluded !== null && excluded <= supply;
  }
  return metrics === null;
};

const checkAffirmativeMetrics = (
  code: unknown,
  classification: unknown,
  reason: unknown,
  adjusted: unknown,
  metrics: unknown,
): metrics is JsonObject => {
  if (
    !hasExactKeys(metrics, [
      "basis",
      "supplyRaw",
      "accountsConsidered",
      "excludedCount",
      "excludedAmountRaw",
      "top1Bps",
      "top5Bps",
      "top10Bps",
      "top1AmountRaw",
      "top5AmountRaw",
      "top10AmountRaw",
    ]) ||
    metrics.basis !== "total_supply" ||
    !isPositiveDigits(metrics.supplyRaw) ||
    !isPositiveSafeInteger(metrics.accountsConsidered) ||
    !isNonnegativeSafeInteger(metrics.excludedCount) ||
    !isDigits(metrics.excludedAmountRaw) ||
    !isDigits(metrics.top1AmountRaw) ||
    !isDigits(metrics.top5AmountRaw) ||
    !isDigits(metrics.top10AmountRaw)
  ) {
    return false;
  }
  for (const key of ["top1Bps", "top5Bps", "top10Bps"] as const) {
    if (!isNonnegativeSafeInteger(metrics[key]) || (metrics[key] as number) > 10_000) return false;
  }

  const supply = BigInt(metrics.supplyRaw);
  const excluded = BigInt(metrics.excludedAmountRaw);
  const top1 = BigInt(metrics.top1AmountRaw);
  const top5 = BigInt(metrics.top5AmountRaw);
  const top10 = BigInt(metrics.top10AmountRaw);
  if (top1 > top5 || top5 > top10 || top10 + excluded > supply) return false;
  if (
    BigInt(metrics.top1Bps as number) !== (top1 * 10_000n) / supply ||
    BigInt(metrics.top5Bps as number) !== (top5 * 10_000n) / supply ||
    BigInt(metrics.top10Bps as number) !== (top10 * 10_000n) / supply
  ) return false;
  if (adjusted === false) {
    if (metrics.excludedCount !== 0 || excluded !== 0n) return false;
  } else if (adjusted === true) {
    if (!isPositiveSafeInteger(metrics.excludedCount)) return false;
  } else {
    return false;
  }
  if (metrics.accountsConsidered === 1 && (top1 !== top5 || top5 !== top10)) return false;
  if ((metrics.accountsConsidered as number) <= 5 && top5 !== top10) return false;

  let expectedCode: string;
  let expectedClassification: string;
  let expectedReason: string;
  if ((metrics.top1Bps as number) >= 3_000) {
    expectedCode = "holders.concentration_high";
    expectedClassification = "high_concentration";
    expectedReason = "top1_share_at_or_above_threshold";
  } else if ((metrics.top5Bps as number) >= 5_000) {
    expectedCode = "holders.concentration_high";
    expectedClassification = "high_concentration";
    expectedReason = "top5_share_at_or_above_threshold";
  } else if ((metrics.top10Bps as number) >= 6_000) {
    expectedCode = "holders.concentration_high";
    expectedClassification = "high_concentration";
    expectedReason = "top10_share_at_or_above_threshold";
  } else if ((metrics.top10Bps as number) >= 3_000) {
    expectedCode = "holders.concentration_moderate";
    expectedClassification = "moderate_concentration";
    expectedReason = "top10_share_moderate";
  } else {
    expectedCode = "holders.distributed";
    expectedClassification = "distributed";
    expectedReason = "top10_share_below_moderate_threshold";
  }
  return code === expectedCode && classification === expectedClassification && reason === expectedReason;
};

type AddRulesReason = (reason: (typeof RULES_REASON_ORDER)[number]) => void;

const validateAttemptIntrinsic = (
  attempt: JsonObject,
  receipt: JsonObject,
  add: AddRulesReason,
): void => {
  if (
    !hasExactKeys(attempt, [
      "version",
      "state",
      "source",
      "result",
      "reason",
      "mintAddress",
      "commitment",
      "attemptedChecks",
      "observation",
    ])
  ) {
    add("holder_attempt_shape_invalid");
  }
  if (attempt.version !== "raven-holder-attempt/v1") add("holder_attempt_version_invalid");
  if (attempt.state !== "attempted_unavailable" && attempt.state !== "observed") {
    add("holder_attempt_state_invalid");
  }
  if (attempt.source !== "solana_rpc") add("holder_attempt_source_invalid");
  if (
    (attempt.state === "attempted_unavailable" && attempt.result !== "unavailable") ||
    (attempt.state === "observed" && attempt.result !== "observed") ||
    (attempt.state !== "attempted_unavailable" && attempt.state !== "observed")
  ) {
    add("holder_attempt_result_invalid");
  }
  if (
    (attempt.state === "attempted_unavailable" &&
      (typeof attempt.reason !== "string" || !UNAVAILABLE_REASONS.has(attempt.reason))) ||
    (attempt.state === "observed" && attempt.reason !== null)
  ) {
    add("holder_attempt_reason_invalid");
  }
  if (!isSolanaAddress(attempt.mintAddress) || attempt.mintAddress !== receipt.mintAddress) {
    add("holder_attempt_mint_mismatch");
  }
  if (
    typeof attempt.commitment !== "string" ||
    !new Set(["finalized", "confirmed", "processed"]).has(attempt.commitment)
  ) {
    add("holder_attempt_commitment_mismatch");
  }
  if (!isCanonicalAttemptedChecks(attempt.attemptedChecks)) {
    add("holder_attempt_checks_invalid");
  }

  if (attempt.observation === null) {
    if (
      attempt.state === "observed" ||
      (typeof attempt.reason === "string" && COHERENT_UNAVAILABLE_REASONS.has(attempt.reason))
    ) {
      add("holder_attempt_observation_invalid");
    }
    return;
  }
  if (!isObject(attempt.observation)) {
    add("holder_attempt_observation_invalid");
    return;
  }
  const observation = attempt.observation;
  if (
    !hasExactKeys(observation, ["slot", "contexts"]) ||
    !isPositiveSafeInteger(observation.slot) ||
    !hasExactKeys(observation.contexts, [
      "mint",
      "metadata",
      "largestAccounts",
      "supply",
      "venueCustody",
      "liquidity",
    ]) ||
    !Object.values(observation.contexts).every((value) => typeof value === "boolean") ||
    observation.contexts.mint !== true ||
    observation.contexts.largestAccounts !== true ||
    observation.contexts.supply !== true ||
    (typeof attempt.reason === "string" && PRE_OBSERVATION_REASONS.has(attempt.reason))
  ) {
    add("holder_attempt_observation_invalid");
  }
  if (observation.slot !== receipt.slot) add("holder_observation_slot_mismatch");
};

const evaluateRules114 = (receipt: JsonObject): string[] => {
  const found = new Set<string>();
  const add = (reason: (typeof RULES_REASON_ORDER)[number]): void => {
    found.add(reason);
  };

  const findings = Array.isArray(receipt.findings) ? receipt.findings : [];
  const holderFindings = findings.filter(
    (finding): finding is JsonObject => isObject(finding) && HOLDER_DERIVED.has(String(finding.code)),
  );
  if (
    findings.some(
      (finding) =>
        isObject(finding) &&
        findingHasUnexpectedHolderAttempt(
          finding,
          HOLDER_DERIVED.has(String(finding.code)),
        ),
    )
  ) {
    add("holder_attempt_unexpected");
  }
  const primaries = holderFindings.filter((finding) => HOLDER_PRIMARY.has(String(finding.code)));
  const affirmatives = primaries.filter((finding) => HOLDER_AFFIRMATIVE.has(String(finding.code)));
  const unresolved = primaries.filter((finding) => finding.code === "holders.distribution_unresolved");
  const qualifiers = holderFindings.filter((finding) => HOLDER_QUALIFIERS.has(String(finding.code)));
  const venueFindings = holderFindings.filter((finding) => HOLDER_VENUE.has(String(finding.code)));

  let state: HolderState = "not_requested";
  if (unresolved.length > 0) state = "attempted_unavailable";
  if (affirmatives.length > 0) state = "observed";

  if (
    primaries.length > 1 ||
    (unresolved.length > 0 && affirmatives.length > 0)
  ) {
    add("holder_primary_cardinality_invalid");
    add("holder_state_contradiction");
  }
  if (state === "not_requested" && (qualifiers.length > 0 || venueFindings.length > 0)) {
    add("holder_primary_cardinality_invalid");
    add("holder_state_contradiction");
  }
  if (
    state === "attempted_unavailable" &&
    (unresolved.length !== 1 || qualifiers.length !== 0 || venueFindings.length !== 0)
  ) {
    add("holder_state_contradiction");
    if (qualifiers.length !== 0) add("holder_qualifier_cardinality_invalid");
    if (venueFindings.length !== 0) add("holder_venue_state_contradiction");
  }
  if (state === "observed") {
    if (affirmatives.length !== 1) add("holder_primary_cardinality_invalid");
    if (qualifiers.length !== 1) add("holder_qualifier_cardinality_invalid");
    if (venueFindings.length > 1) add("holder_venue_state_contradiction");
  }

  const attempts: JsonObject[] = [];
  let primaryEvidence: JsonObject | null = null;
  let qualifierEvidence: JsonObject | null = null;

  for (const finding of holderFindings) {
    if (!hasExactKeys(finding, ["code", "source", "subject", "evidence"])) {
      add("holder_finding_shape_invalid");
    }
    if (finding.source !== "holder_distribution_evidence") add("holder_finding_source_invalid");
    const expectedSubject = HOLDER_PRIMARY.has(String(finding.code))
      ? "holder_concentration"
      : HOLDER_QUALIFIERS.has(String(finding.code))
        ? "holder_concentration_basis"
        : "venue_custody_state";
    if (finding.subject !== expectedSubject) add("holder_finding_subject_invalid");

    const evidence = isObject(finding.evidence) ? finding.evidence : null;
    if (!evidence) {
      add("holder_finding_evidence_invalid");
      add("holder_attempt_missing");
      continue;
    }
    if (!("holderAttempt" in evidence)) add("holder_attempt_missing");
    else if (isObject(evidence.holderAttempt)) attempts.push(evidence.holderAttempt);
    else add("holder_attempt_shape_invalid");

    if (HOLDER_PRIMARY.has(String(finding.code))) {
      if (primaryEvidence === null) primaryEvidence = evidence;
      if (
        !hasExactKeys(evidence, [
          "classification",
          "reason",
          "classifierVersion",
          "adjustedForKnownVenues",
          "exclusionEvidence",
          "metrics",
          "holderAttempt",
        ]) ||
        evidence.classifierVersion !== "holders-classifier/1" ||
        typeof evidence.adjustedForKnownVenues !== "boolean" ||
        !(evidence.exclusionEvidence === null || isNonemptyString(evidence.exclusionEvidence))
      ) {
        add("holder_finding_evidence_invalid");
      }

      if (finding.code === "holders.distribution_unresolved") {
        if (
          evidence.classification !== "unresolved" ||
          typeof evidence.reason !== "string" ||
          !UNAVAILABLE_REASONS.has(evidence.reason) ||
          !checkUnavailableMetrics(evidence.reason, evidence.metrics)
        ) {
          add("holder_finding_evidence_invalid");
        }
        if (evidence.reason === "all_accounts_excluded") {
          if (
            evidence.adjustedForKnownVenues !== true ||
            !isNonemptyString(evidence.exclusionEvidence)
          ) {
            add("holder_finding_evidence_invalid");
          }
        } else if (
          evidence.adjustedForKnownVenues !== false ||
          evidence.exclusionEvidence !== null
        ) {
          add("holder_finding_evidence_invalid");
        }
      } else {
        if (
          !checkAffirmativeMetrics(
            finding.code,
            evidence.classification,
            evidence.reason,
            evidence.adjustedForKnownVenues,
            evidence.metrics,
          )
        ) {
          add("holder_finding_evidence_invalid");
        } else if (evidence.adjustedForKnownVenues === true) {
          if (
            !isNonemptyString(evidence.exclusionEvidence) ||
            !isPositiveSafeInteger(evidence.metrics.excludedCount)
          ) {
            add("holder_finding_evidence_invalid");
          }
        } else if (evidence.exclusionEvidence !== null) {
          add("holder_finding_evidence_invalid");
        }
      }
    } else if (HOLDER_QUALIFIERS.has(String(finding.code))) {
      if (qualifierEvidence === null) qualifierEvidence = evidence;
      if (
        !hasExactKeys(evidence, [
          "adjustedForKnownVenues",
          "exclusionEvidence",
          "excludedCount",
          "holderAttempt",
        ])
      ) {
        add("holder_finding_evidence_invalid");
      }
      if (finding.code === "holders.adjusted_for_known_venues") {
        if (
          evidence.adjustedForKnownVenues !== true ||
          !isNonemptyString(evidence.exclusionEvidence) ||
          !isPositiveSafeInteger(evidence.excludedCount)
        ) {
          add("holder_finding_evidence_invalid");
        }
      } else if (
        evidence.adjustedForKnownVenues !== false ||
        evidence.exclusionEvidence !== null ||
        evidence.excludedCount !== 0
      ) {
        add("holder_finding_evidence_invalid");
      }
    } else {
      if (
        !hasExactKeys(evidence, [
          "venue",
          "curveAddress",
          "complete",
          "realTokenReservesRaw",
          "realSolReservesRaw",
          "holderAttempt",
        ]) ||
        evidence.venue !== "pumpfun_bonding_curve" ||
        !isSolanaAddress(evidence.curveAddress) ||
        !(
          evidence.realTokenReservesRaw === null || isDigits(evidence.realTokenReservesRaw)
        ) ||
        !(evidence.realSolReservesRaw === null || isDigits(evidence.realSolReservesRaw)) ||
        (finding.code === "venue.pumpfun_curve_active" && evidence.complete !== false) ||
        (finding.code === "venue.pumpfun_curve_complete" && evidence.complete !== true)
      ) {
        add("holder_finding_evidence_invalid");
      }
    }
  }

  if (attempts.length > 0) {
    const first = attempts[0];
    if (attempts.some((attempt) => !canonicalEqual(first, attempt))) {
      add("holder_attempt_copy_mismatch");
    }
  }
  for (const copiedAttempt of attempts) validateAttemptIntrinsic(copiedAttempt, receipt, add);
  const attempt = attempts[0] ?? null;
  if (attempt) {
    if (state === "attempted_unavailable" && attempt.state !== "attempted_unavailable") {
      add("holder_state_contradiction");
    }
    if (state === "observed" && attempt.state !== "observed") add("holder_state_contradiction");
    if (
      primaries[0]?.code === "holders.distribution_unresolved" &&
      primaryEvidence &&
      primaryEvidence.reason !== attempt.reason
    ) {
      add("holder_finding_evidence_invalid");
    }

    const checks = attempt.attemptedChecks;
    const reason = attempt.reason;
    let checksValid = true;
    if (attempt.state === "attempted_unavailable") {
      if (reason === "holder_fetch_failed" || reason === "holder_decode_failed") {
        checksValid = exactChecks(checks, ["largest_accounts"]);
      } else if (reason === "supply_fetch_failed") {
        checksValid = exactChecks(checks, ["largest_accounts", "token_supply"]);
      } else if (
        reason === "holder_observation_slot_missing" ||
        reason === "holder_observation_slot_mismatch"
      ) {
        checksValid = exactChecks(
          checks,
          ["largest_accounts", "token_supply"],
          ["venue_custody", "liquidity_coherence"],
        );
      } else if (
        reason === "zero_total_supply" ||
        reason === "no_holder_accounts_returned" ||
        reason === "holder_amounts_exceed_supply"
      ) {
        checksValid = exactChecks(
          checks,
          ["largest_accounts", "token_supply"],
          ["liquidity_coherence"],
        );
      } else if (reason === "all_accounts_excluded") {
        checksValid = exactChecks(
          checks,
          ["largest_accounts", "token_supply", "venue_custody"],
          ["liquidity_coherence"],
        );
      } else {
        checksValid = exactChecks(
          checks,
          ["largest_accounts", "token_supply"],
          ["venue_custody", "liquidity_coherence"],
        );
      }
    } else if (attempt.state === "observed") {
      checksValid = exactChecks(
        checks,
        ["largest_accounts", "token_supply"],
        ["venue_custody", "liquidity_coherence"],
      );
    }
    if (!checksValid) add("holder_attempt_checks_invalid");

    const observation = attempt.observation;
    const contexts = observation && typeof observation === "object"
      ? (observation as JsonObject).contexts
      : null;
    if (contexts) {
      const contextRecord = contexts as JsonObject;
      const metadataExpected = has(receipt.scopeChecksPerformed, "metadata_mutability");
      const metadataFindingPresent = findings.some(
        (finding) =>
          isObject(finding) &&
          finding.code === "issuer_control.metadata_mutable" &&
          finding.subject === "metadata_mutability",
      );
      if (
        contextRecord.metadata !== metadataExpected ||
        (metadataFindingPresent && contextRecord.metadata !== true)
      ) {
        add("holder_metadata_context_mismatch");
      }
      const liquidityExpected = findings.some(
        (finding) => isObject(finding) && LIQUIDITY_FINDINGS.has(String(finding.code)),
      );
      if (
        contextRecord.liquidity !== liquidityExpected ||
        (liquidityExpected && !has(checks, "liquidity_coherence"))
      ) {
        add("holder_liquidity_context_mismatch");
      }

      const adjusted = qualifiers[0]?.code === "holders.adjusted_for_known_venues";
      const venueExpected = adjusted || venueFindings.length > 0;
      if (
        contextRecord.venueCustody !== venueExpected ||
        (venueExpected && !has(checks, "venue_custody")) ||
        (qualifiers.some((finding) => finding.code === "holders.unadjusted_may_include_pools") &&
          contextRecord.venueCustody !== false)
      ) {
        add("holder_venue_context_mismatch");
      }
    }
  }

  if (state === "observed" && primaryEvidence && qualifierEvidence) {
    const metrics = isObject(primaryEvidence.metrics) ? primaryEvidence.metrics : null;
    if (
      primaryEvidence.adjustedForKnownVenues !== qualifierEvidence.adjustedForKnownVenues ||
      primaryEvidence.exclusionEvidence !== qualifierEvidence.exclusionEvidence ||
      !metrics ||
      metrics.excludedCount !== qualifierEvidence.excludedCount
    ) {
      add("holder_finding_evidence_invalid");
    }
  }

  const coverage = receipt.coverageGaps;
  const performed = receipt.scopeChecksPerformed;
  const notPerformed = receipt.scopeChecksNotPerformed;
  if (isStringArray(performed) && isStringArray(notPerformed)) {
    if (
      !isUniqueStringArray(performed) ||
      !isUniqueStringArray(notPerformed) ||
      performed.some((check) => notPerformed.includes(check))
    ) {
      add("holder_scope_checks_invalid");
    }
    const metadataFinding = findings.some(
      (finding) =>
        isObject(finding) &&
        finding.code === "issuer_control.metadata_mutable" &&
        finding.subject === "metadata_mutability",
    );
    if (
      metadataFinding &&
      (!performed.includes("metadata_mutability") ||
        notPerformed.includes("metadata_mutability"))
    ) {
      add("holder_scope_checks_invalid");
    }
  }
  if (!isUniqueStringArray(coverage)) add("holder_coverage_gap_invalid");
  if (state === "not_requested" || state === "attempted_unavailable") {
    if (!has(coverage, "top_holders")) add("holder_coverage_gap_invalid");
    if (has(performed, "top_holders") || !has(notPerformed, "top_holders")) {
      add("holder_scope_checks_invalid");
    }
  } else if (state === "observed") {
    if (has(coverage, "top_holders")) add("holder_coverage_gap_invalid");
    if (!has(performed, "top_holders") || has(notPerformed, "top_holders")) {
      add("holder_scope_checks_invalid");
    }
  }
  if (state === "attempted_unavailable") {
    if (!isStringArray(coverage) || coverage.length === 0) add("holder_coverage_gap_invalid");
    const allExcluded = primaryEvidence?.reason === "all_accounts_excluded";
    if (has(coverage, "holder_venue_adjustment") === allExcluded) {
      add("holder_coverage_gap_invalid");
    }
  }
  if (state === "observed" && primaryEvidence) {
    const adjusted = qualifiers[0]?.code === "holders.adjusted_for_known_venues";
    if (has(coverage, "holder_venue_adjustment") === adjusted) {
      add("holder_coverage_gap_invalid");
    }
  }

  return RULES_REASON_ORDER.filter((reason) => found.has(reason));
};

/**
 * Classify the signed rules identity without conflating it with receipt
 * integrity, freshness, or caller key trust.
 */
export const evaluateReceiptRules = (
  receipt: unknown,
  coreValid: boolean,
): ReceiptRulesResult => {
  const version = isObject(receipt) && typeof receipt.rulesVersion === "string"
    ? receipt.rulesVersion
    : null;

  if (version === null) {
    return {
      rulesVersion: null,
      rulesStatus: "malformed",
      rulesReasons: ["malformed_rules_version"],
    };
  }
  if (!coreValid) return { rulesVersion: version, rulesStatus: null, rulesReasons: [] };
  if (!CANONICAL_RULES_VERSION.test(version)) {
    return {
      rulesVersion: version,
      rulesStatus: "malformed",
      rulesReasons: ["malformed_rules_version"],
    };
  }
  if (HISTORICAL_RULES.has(version)) {
    return { rulesVersion: version, rulesStatus: "supported_valid", rulesReasons: [] };
  }
  if (version !== RULES_1_1_4) {
    return {
      rulesVersion: version,
      rulesStatus: "unsupported",
      rulesReasons: ["unsupported_rules_version"],
    };
  }

  const rulesReasons = evaluateRules114(receipt as JsonObject);
  return {
    rulesVersion: version,
    rulesStatus: rulesReasons.length === 0 ? "supported_valid" : "supported_invalid",
    rulesReasons,
  };
};
