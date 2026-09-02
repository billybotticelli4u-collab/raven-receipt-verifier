'use strict';

const {
  COMMITMENTS,
  HOLDER_ATTEMPT_CHECKS,
  HOLDER_ATTEMPT_VERSION,
  HOLDER_CLASSIFICATIONS_V1,
  HOLDER_FINDING_SOURCE,
  HOLDER_UNAVAILABLE_REASONS,
  RULES_VERSION_1_1_4,
  exactKeys,
  isDigitString,
  isPositiveSafeInteger,
  isSolanaAddress,
} = require('./holderAttempt');
const {
  classifyFindingEnvelopeOutcome,
} = require('../raven-solana-outcome/outcomeRules');

const HISTORICAL_RULES_VERSIONS = new Set([
  'raven-rules@1.0.0',
  'raven-rules@1.1.0',
  'raven-rules@1.1.1',
  'raven-rules@1.1.2',
  'raven-rules@1.1.3',
]);

const PRIMARY_CODES = new Set([
  'holders.concentration_high',
  'holders.concentration_moderate',
  'holders.distributed',
  'holders.distribution_unresolved',
]);
const AFFIRMATIVE_CODES = new Set([
  'holders.concentration_high',
  'holders.concentration_moderate',
  'holders.distributed',
]);
const QUALIFIER_CODES = new Set([
  'holders.adjusted_for_known_venues',
  'holders.unadjusted_may_include_pools',
]);
const VENUE_CODES = new Set([
  'venue.pumpfun_curve_active',
  'venue.pumpfun_curve_complete',
]);
const HOLDER_DERIVED_CODES = new Set([
  ...PRIMARY_CODES,
  ...QUALIFIER_CODES,
  ...VENUE_CODES,
]);
const LIQUIDITY_CODES = new Set([
  'venue.liquidity_locked',
  'venue.liquidity_partially_locked',
  'venue.liquidity_withdrawable',
  'venue.liquidity_unresolved',
  'liquidity.curve_active_protocol_custody',
  'liquidity.pumpswap_canonical_pool_present',
  'liquidity.supply_majority_returned_to_pool',
]);
const REASON_ORDER = Object.freeze([
  'producer_context_invalid',
  'holder_attempt_not_executed',
  'holder_attempt_not_completed',
  'holder_not_selected_but_present',
  'holder_attempt_unexpected',
  'finding_codes_mismatch',
  'holder_finding_shape_invalid',
  'holder_finding_source_invalid',
  'holder_finding_subject_invalid',
  'holder_finding_evidence_invalid',
  'holder_primary_cardinality_invalid',
  'holder_state_contradiction',
  'holder_qualifier_cardinality_invalid',
  'holder_venue_state_contradiction',
  'holder_attempt_missing',
  'holder_attempt_shape_invalid',
  'holder_attempt_version_invalid',
  'holder_attempt_state_invalid',
  'holder_attempt_source_invalid',
  'holder_attempt_result_invalid',
  'holder_attempt_reason_invalid',
  'holder_attempt_mint_mismatch',
  'holder_attempt_commitment_mismatch',
  'holder_attempt_checks_invalid',
  'holder_attempt_observation_invalid',
  'holder_attempt_copy_mismatch',
  'holder_attempt_expectation_mismatch',
  'holder_classifier_expectation_mismatch',
  'holder_observation_slot_mismatch',
  'holder_metadata_context_mismatch',
  'holder_liquidity_context_mismatch',
  'holder_venue_context_mismatch',
  'holder_coverage_gap_invalid',
  'holder_scope_checks_invalid',
]);

const PRIMARY_EVIDENCE_KEYS = [
  'classification',
  'reason',
  'classifierVersion',
  'adjustedForKnownVenues',
  'exclusionEvidence',
  'metrics',
  'holderAttempt',
];
const QUALIFIER_EVIDENCE_KEYS = [
  'adjustedForKnownVenues',
  'exclusionEvidence',
  'excludedCount',
  'holderAttempt',
];
const VENUE_EVIDENCE_KEYS = [
  'venue',
  'curveAddress',
  'complete',
  'realTokenReservesRaw',
  'realSolReservesRaw',
  'holderAttempt',
];
const ATTEMPT_KEYS = [
  'version',
  'state',
  'source',
  'result',
  'reason',
  'mintAddress',
  'commitment',
  'attemptedChecks',
  'observation',
];
const CONTEXT_KEYS = [
  'mint',
  'metadata',
  'largestAccounts',
  'supply',
  'venueCustody',
  'liquidity',
];

const PRIMARY_MAPPING = Object.freeze({
  'holders.concentration_high': {
    classification: 'high_concentration',
    reasons: new Set([
      'top1_share_at_or_above_threshold',
      'top5_share_at_or_above_threshold',
      'top10_share_at_or_above_threshold',
    ]),
  },
  'holders.concentration_moderate': {
    classification: 'moderate_concentration',
    reasons: new Set(['top10_share_moderate']),
  },
  'holders.distributed': {
    classification: 'distributed',
    reasons: new Set(['top10_share_below_moderate_threshold']),
  },
});

const PRE_OBSERVATION_REASONS = new Set([
  'holder_fetch_failed',
  'holder_decode_failed',
  'supply_fetch_failed',
  'holder_observation_slot_missing',
  'holder_observation_slot_mismatch',
]);
const COHERENT_UNAVAILABLE_REASONS = new Set([
  'zero_total_supply',
  'no_holder_accounts_returned',
  'holder_amounts_exceed_supply',
  'all_accounts_excluded',
]);

function arrayOfUniqueStrings(value) {
  return Array.isArray(value) &&
    value.every((entry) => typeof entry === 'string') &&
    new Set(value).size === value.length;
}

function exactArray(left, right) {
  return Array.isArray(left) && Array.isArray(right) &&
    left.length === right.length && left.every((entry, index) => entry === right[index]);
}

// A 1.1.4 holder attempt has exactly one semantic location: the own enumerable
// data property `findings[i].evidence.holderAttempt` of a holder-derived
// finding. Do not let accessors, prototypes, symbols, non-enumerable fields or
// aliases create a second representation that ordinary Object.keys/JSON would
// silently omit. The snapshot is also the only findings graph this validator
// reads after the boundary, so a Proxy that changes after descriptor inspection
// cannot change the admitted state.
const ADMISSION_SNAPSHOT_BUDGET = 131072;

function inheritedHolderAttempt(object) {
  let prototype;
  try {
    prototype = Object.getPrototypeOf(object);
  } catch {
    return true;
  }
  while (prototype !== null) {
    try {
      if (Object.prototype.hasOwnProperty.call(prototype, 'holderAttempt')) return true;
      prototype = Object.getPrototypeOf(prototype);
    } catch {
      return true;
    }
  }
  return false;
}

function snapshotAdmissionFindings(value) {
  if (!Array.isArray(value)) {
    return { ok: true, value: [], unexpectedHolderAttempt: false };
  }
  const root = [];
  const stack = [{ kind: 'enter', source: value, target: root, context: 'root_array' }];
  const ancestors = new WeakSet();
  const created = [];
  let unexpectedHolderAttempt = false;
  let work = 0;

  const fail = (holderAttempt) => ({
    ok: false,
    holderAttempt: holderAttempt === true,
  });
  const primitive = (entry) =>
    entry === null || typeof entry === 'string' || typeof entry === 'boolean' ||
    (typeof entry === 'number' && Number.isFinite(entry));
  const isArrayIndex = (key) => /^(?:0|[1-9][0-9]*)$/.test(key) &&
    Number.isSafeInteger(Number(key)) && Number(key) >= 0 && Number(key) < 4294967295;

  try {
    while (stack.length > 0) {
      const frame = stack.pop();
      if (frame.kind === 'exit') {
        ancestors.delete(frame.source);
        continue;
      }
      if (work >= ADMISSION_SNAPSHOT_BUDGET) return fail(false);
      work += 1;
      if (ancestors.has(frame.source)) return fail(false);
      ancestors.add(frame.source);
      created.push(frame.target);

      const symbols = Object.getOwnPropertySymbols(frame.source);
      if (symbols.length > 0) return fail(true);
      const children = [];
      const holderFinding = frame.context === 'finding' && (() => {
        const descriptor = Object.getOwnPropertyDescriptor(frame.source, 'code');
        return Boolean(descriptor && Object.prototype.hasOwnProperty.call(descriptor, 'value') &&
          HOLDER_DERIVED_CODES.has(descriptor.value));
      })();
      const add = (key, descriptor, context) => {
        const holderAttempt = key === 'holderAttempt';
        if (holderAttempt && frame.context !== 'holder_evidence') {
          unexpectedHolderAttempt = true;
        }
        if (!descriptor || !Object.prototype.hasOwnProperty.call(descriptor, 'value') ||
            descriptor.enumerable !== true) {
          return fail(holderAttempt || unexpectedHolderAttempt);
        }
        const entry = descriptor.value;
        if (primitive(entry)) {
          if (Array.isArray(frame.target)) frame.target[key] = entry;
          else Object.defineProperty(frame.target, key, {
            value: entry, enumerable: true, configurable: false, writable: false,
          });
          return null;
        }
        if (entry === undefined || typeof entry !== 'object') {
          return fail(holderAttempt || unexpectedHolderAttempt);
        }
        const child = Array.isArray(entry) ? [] : Object.create(null);
        if (Array.isArray(frame.target)) frame.target[key] = child;
        else Object.defineProperty(frame.target, key, {
          value: child, enumerable: true, configurable: false, writable: false,
        });
        children.push({ kind: 'enter', source: entry, target: child, context });
        return null;
      };

      if (Array.isArray(frame.source)) {
        if (Object.getPrototypeOf(frame.source) !== Array.prototype || inheritedHolderAttempt(frame.source)) {
          return fail(true);
        }
        const lengthDescriptor = Object.getOwnPropertyDescriptor(frame.source, 'length');
        if (!lengthDescriptor || !Object.prototype.hasOwnProperty.call(lengthDescriptor, 'value') ||
            !Number.isSafeInteger(lengthDescriptor.value) || lengthDescriptor.value < 0) {
          return fail(false);
        }
        const length = lengthDescriptor.value;
        const names = Object.getOwnPropertyNames(frame.source);
        if (names.length !== length + 1 || !names.includes('length')) return fail(false);
        for (let index = 0; index < length; index += 1) {
          if (work >= ADMISSION_SNAPSHOT_BUDGET) return fail(false);
          work += 1;
          const key = String(index);
          if (!isArrayIndex(key)) return fail(false);
          const failure = add(
            index,
            Object.getOwnPropertyDescriptor(frame.source, key),
            frame.context === 'root_array' ? 'finding' : 'nested',
          );
          if (failure) return failure;
        }
      } else {
        const prototype = Object.getPrototypeOf(frame.source);
        if (inheritedHolderAttempt(frame.source)) return fail(true);
        if (prototype !== Object.prototype && prototype !== null) return fail(false);
        for (const key of Object.getOwnPropertyNames(frame.source)) {
          if (work >= ADMISSION_SNAPSHOT_BUDGET) return fail(false);
          work += 1;
          const failure = add(
            key,
            Object.getOwnPropertyDescriptor(frame.source, key),
            frame.context === 'finding' && key === 'evidence' && holderFinding
              ? 'holder_evidence'
              : 'nested',
          );
          if (failure) return failure;
        }
      }
      stack.push({ kind: 'exit', source: frame.source });
      for (let index = children.length - 1; index >= 0; index -= 1) stack.push(children[index]);
    }
  } catch {
    return fail(true);
  }

  for (let index = created.length - 1; index >= 0; index -= 1) Object.freeze(created[index]);
  return { ok: true, value: root, unexpectedHolderAttempt };
}

// Holder provenance has a closed, shallow grammar. Compare malformed values
// iteratively and under a fixed work budget so a custom engine cannot turn a
// deeply nested attempt/classifier field into recursion or admission failure.
function boundedStructuralEqual(left, right, maxNodes = 512) {
  const stack = [[left, right]];
  const seenLeft = new WeakSet();
  const seenRight = new WeakSet();
  let nodes = 0;
  while (stack.length > 0) {
    if (nodes >= maxNodes) return false;
    nodes += 1;
    const [a, b] = stack.pop();
    if (Object.is(a, b)) continue;
    if (typeof a !== typeof b || a === null || b === null ||
        typeof a !== 'object') return false;
    if (seenLeft.has(a) || seenRight.has(b)) return false;
    seenLeft.add(a);
    seenRight.add(b);
    if (Array.isArray(a) !== Array.isArray(b)) return false;
    if (Array.isArray(a)) {
      if (a.length !== b.length || a.length + nodes > maxNodes) return false;
      for (let index = 0; index < a.length; index += 1) {
        stack.push([a[index], b[index]]);
      }
      continue;
    }
    const keysA = Object.keys(a).sort();
    const keysB = Object.keys(b).sort();
    if (!exactArray(keysA, keysB) || keysA.length + nodes > maxNodes) return false;
    for (const key of keysA) stack.push([a[key], b[key]]);
  }
  return true;
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isNullOrDigitString(value) {
  return value === null || isDigitString(value);
}

function isPositiveDigitString(value) {
  return typeof value === 'string' && /^[1-9][0-9]*$/.test(value);
}

function isNonnegativeSafeInteger(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function isBps(value) {
  return isNonnegativeSafeInteger(value) && value <= 10000;
}

function digitBigInt(value) {
  if (!isDigitString(value)) return null;
  try {
    return BigInt(value);
  } catch {
    return null;
  }
}

function validAffirmativeMetrics(reason, metrics, adjusted) {
  if (!exactKeys(metrics, [
    'basis', 'supplyRaw', 'accountsConsidered', 'excludedCount',
    'excludedAmountRaw', 'top1Bps', 'top5Bps', 'top10Bps',
    'top1AmountRaw', 'top5AmountRaw', 'top10AmountRaw',
  ]) || metrics.basis !== 'total_supply' || !isPositiveDigitString(metrics.supplyRaw) ||
      !isPositiveSafeInteger(metrics.accountsConsidered) ||
      !isNonnegativeSafeInteger(metrics.excludedCount) ||
      !isDigitString(metrics.excludedAmountRaw) ||
      !isBps(metrics.top1Bps) || !isBps(metrics.top5Bps) || !isBps(metrics.top10Bps) ||
      !isDigitString(metrics.top1AmountRaw) || !isDigitString(metrics.top5AmountRaw) ||
      !isDigitString(metrics.top10AmountRaw)) {
    return false;
  }
  if ((!adjusted && (metrics.excludedCount !== 0 || metrics.excludedAmountRaw !== '0')) ||
      (adjusted && !isPositiveSafeInteger(metrics.excludedCount))) {
    return false;
  }
  const supply = digitBigInt(metrics.supplyRaw);
  const excluded = digitBigInt(metrics.excludedAmountRaw);
  const top1 = digitBigInt(metrics.top1AmountRaw);
  const top5 = digitBigInt(metrics.top5AmountRaw);
  const top10 = digitBigInt(metrics.top10AmountRaw);
  if (supply === null || excluded === null || top1 === null || top5 === null ||
      top10 === null || supply <= 0n || top1 > top5 || top5 > top10 ||
      top10 + excluded > supply) {
    return false;
  }
  if ((metrics.accountsConsidered === 1 && (top1 !== top5 || top5 !== top10)) ||
      (metrics.accountsConsidered <= 5 && top5 !== top10)) {
    return false;
  }
  if (metrics.top1Bps !== Number((top1 * 10000n) / supply) ||
      metrics.top5Bps !== Number((top5 * 10000n) / supply) ||
      metrics.top10Bps !== Number((top10 * 10000n) / supply)) {
    return false;
  }
  const expectedReason = metrics.top1Bps >= 3000
    ? 'top1_share_at_or_above_threshold'
    : metrics.top5Bps >= 5000
      ? 'top5_share_at_or_above_threshold'
      : metrics.top10Bps >= 6000
        ? 'top10_share_at_or_above_threshold'
        : metrics.top10Bps >= 3000
          ? 'top10_share_moderate'
          : 'top10_share_below_moderate_threshold';
  return reason === expectedReason;
}

function validMetrics(reason, metrics, adjusted) {
  if (PRE_OBSERVATION_REASONS.has(reason)) return metrics === null && adjusted === false;
  if (reason === 'zero_total_supply' || reason === 'no_holder_accounts_returned') {
    if (!exactKeys(metrics, ['basis', 'supplyRaw']) ||
        metrics.basis !== 'total_supply' || !isDigitString(metrics.supplyRaw) || adjusted !== false) {
      return false;
    }
    const supply = digitBigInt(metrics.supplyRaw);
    return supply !== null && (reason === 'zero_total_supply' ? supply === 0n : supply > 0n);
  }
  if (reason === 'holder_amounts_exceed_supply') {
    const supply = metrics && digitBigInt(metrics.supplyRaw);
    return exactKeys(metrics, ['basis', 'supplyRaw', 'accountsConsidered']) &&
      metrics.basis === 'total_supply' && supply !== null && supply > 0n &&
      isPositiveSafeInteger(metrics.accountsConsidered) && adjusted === false;
  }
  if (reason === 'all_accounts_excluded') {
    if (!exactKeys(metrics, ['basis', 'supplyRaw', 'excludedCount', 'excludedAmountRaw']) ||
        metrics.basis !== 'total_supply' || !isDigitString(metrics.supplyRaw) ||
        !isPositiveSafeInteger(metrics.excludedCount) || !isDigitString(metrics.excludedAmountRaw) ||
        adjusted !== true) {
      return false;
    }
    const supply = digitBigInt(metrics.supplyRaw);
    const excluded = digitBigInt(metrics.excludedAmountRaw);
    return supply !== null && excluded !== null && supply > 0n && excluded <= supply;
  }
  return validAffirmativeMetrics(reason, metrics, adjusted);
}

function validateMode(mode, add) {
  if (!mode || typeof mode !== 'object' || Array.isArray(mode) || mode.mode !== 'producer') {
    if (!exactKeys(mode, ['mode']) || mode.mode !== 'offline') add('producer_context_invalid');
    return { kind: mode && mode.mode === 'offline' ? 'offline' : 'invalid' };
  }
  if (mode.selection === 'not_selected') {
    if (!exactKeys(mode, ['mode', 'selection'])) add('producer_context_invalid');
    return { kind: 'producer', selection: 'not_selected' };
  }
  if (mode.selection !== 'optional' && mode.selection !== 'mandatory') {
    add('producer_context_invalid');
    return { kind: 'invalid' };
  }
  if (mode.execution === 'not_started' || mode.execution === 'started_uncompleted') {
    if (!exactKeys(mode, ['mode', 'selection', 'execution'])) add('producer_context_invalid');
    return { kind: 'producer', selection: mode.selection, execution: mode.execution };
  }
  if (mode.execution !== 'completed' || !exactKeys(mode, ['mode', 'selection', 'execution', 'acquisition'])) {
    add('producer_context_invalid');
    return { kind: 'invalid' };
  }
  if (!mode.acquisition || !exactKeys(mode.acquisition, ['attempt', 'classification', 'readSlots'])) {
    add('producer_context_invalid');
  } else {
    if (!mode.acquisition.attempt || typeof mode.acquisition.attempt !== 'object' ||
        Array.isArray(mode.acquisition.attempt) ||
        !exactKeys(mode.acquisition.attempt, ATTEMPT_KEYS)) {
      add('producer_context_invalid');
    }
    if (!mode.acquisition.classification ||
        !exactKeys(mode.acquisition.classification, [
          'classification', 'reason', 'classifierVersion',
          'adjustedForKnownVenues', 'exclusionEvidence', 'metrics',
        ]) ||
        !HOLDER_CLASSIFICATIONS_V1.includes(mode.acquisition.classification.classification) ||
        typeof mode.acquisition.classification.reason !== 'string' ||
        mode.acquisition.classification.classifierVersion !== 'holders-classifier/1' ||
        typeof mode.acquisition.classification.adjustedForKnownVenues !== 'boolean') {
      add('producer_context_invalid');
    }
    if (!mode.acquisition.readSlots || typeof mode.acquisition.readSlots !== 'object' ||
        Array.isArray(mode.acquisition.readSlots)) {
      add('producer_context_invalid');
    }
  }
  return {
    kind: 'producer',
    selection: mode.selection,
    execution: 'completed',
    acquisition: mode.acquisition,
  };
}

function validateAttempt(attempt, input, add, present) {
  if (present !== true) {
    add('holder_attempt_missing');
    return false;
  }
  if (!attempt || typeof attempt !== 'object' || Array.isArray(attempt)) {
    add('holder_attempt_shape_invalid');
    return false;
  }
  if (!exactKeys(attempt, ATTEMPT_KEYS)) add('holder_attempt_shape_invalid');
  if (attempt.version !== HOLDER_ATTEMPT_VERSION) add('holder_attempt_version_invalid');
  if (attempt.state !== 'attempted_unavailable' && attempt.state !== 'observed') {
    add('holder_attempt_state_invalid');
  }
  if (attempt.source !== 'solana_rpc') add('holder_attempt_source_invalid');
  if (
    (attempt.state === 'attempted_unavailable' && attempt.result !== 'unavailable') ||
    (attempt.state === 'observed' && attempt.result !== 'observed') ||
    (attempt.state !== 'attempted_unavailable' && attempt.state !== 'observed')
  ) add('holder_attempt_result_invalid');
  if (
    (attempt.state === 'attempted_unavailable' && !HOLDER_UNAVAILABLE_REASONS.includes(attempt.reason)) ||
    (attempt.state === 'observed' && attempt.reason !== null)
  ) add('holder_attempt_reason_invalid');
  if (!isSolanaAddress(attempt.mintAddress) || attempt.mintAddress !== input.mintAddress) {
    add('holder_attempt_mint_mismatch');
  }
  if (
    !COMMITMENTS.includes(attempt.commitment) ||
    (input.commitment !== undefined && attempt.commitment !== input.commitment)
  ) add('holder_attempt_commitment_mismatch');

  const checks = attempt.attemptedChecks;
  const checkIndexes = Array.isArray(checks)
    ? checks.map((check) => HOLDER_ATTEMPT_CHECKS.indexOf(check))
    : [];
  if (
    !arrayOfUniqueStrings(checks) || checks.length === 0 || checks[0] !== 'largest_accounts' ||
    checkIndexes.some((index) => index < 0) ||
    checkIndexes.some((index, position) => position > 0 && index <= checkIndexes[position - 1])
  ) add('holder_attempt_checks_invalid');

  if (attempt.observation === null) {
    if (attempt.state === 'observed' || COHERENT_UNAVAILABLE_REASONS.has(attempt.reason)) {
      add('holder_attempt_observation_invalid');
    }
  } else if (!attempt.observation || typeof attempt.observation !== 'object' ||
      Array.isArray(attempt.observation)) {
    add('holder_attempt_observation_invalid');
  } else {
    const observation = attempt.observation;
    if (
      !exactKeys(observation, ['slot', 'contexts']) ||
      !isPositiveSafeInteger(observation.slot) ||
      !exactKeys(observation.contexts, CONTEXT_KEYS) ||
      CONTEXT_KEYS.some((key) => typeof observation.contexts[key] !== 'boolean') ||
      observation.contexts.mint !== true ||
      (observation.contexts.largestAccounts !== true || observation.contexts.supply !== true) ||
      PRE_OBSERVATION_REASONS.has(attempt.reason)
    ) add('holder_attempt_observation_invalid');
    if (input.observedSlot !== observation.slot) add('holder_observation_slot_mismatch');
  }
  return true;
}

function validatePrimary(primary, add) {
  if (!primary || !primary.evidence || typeof primary.evidence !== 'object') return;
  const evidence = primary.evidence;
  if (!exactKeys(evidence, PRIMARY_EVIDENCE_KEYS)) {
    add('holder_finding_evidence_invalid');
    return;
  }
  if (!HOLDER_CLASSIFICATIONS_V1.includes(evidence.classification) ||
      evidence.classifierVersion !== 'holders-classifier/1' ||
      typeof evidence.adjustedForKnownVenues !== 'boolean') {
    add('holder_finding_evidence_invalid');
  }
  if (primary.code === 'holders.distribution_unresolved') {
    const attemptIsPlainObject = Boolean(
      evidence.holderAttempt &&
      typeof evidence.holderAttempt === 'object' &&
      !Array.isArray(evidence.holderAttempt),
    );
    if (evidence.classification !== 'unresolved' ||
        !HOLDER_UNAVAILABLE_REASONS.includes(evidence.reason) ||
        (attemptIsPlainObject && evidence.reason !== evidence.holderAttempt.reason) ||
        !validMetrics(evidence.reason, evidence.metrics, evidence.adjustedForKnownVenues)) {
      add('holder_finding_evidence_invalid');
    }
  } else {
    const mapping = PRIMARY_MAPPING[primary.code];
    if (!mapping || evidence.classification !== mapping.classification ||
        !mapping.reasons.has(evidence.reason) ||
        !validMetrics(evidence.reason, evidence.metrics, evidence.adjustedForKnownVenues)) {
      add('holder_finding_evidence_invalid');
    }
  }
  if (evidence.adjustedForKnownVenues) {
    if (!isNonEmptyString(evidence.exclusionEvidence) ||
        !evidence.metrics || !isPositiveSafeInteger(evidence.metrics.excludedCount)) {
      add('holder_finding_evidence_invalid');
    }
  } else if (evidence.exclusionEvidence !== null) {
    add('holder_finding_evidence_invalid');
  }
}

function validateQualifier(qualifier, primary, add) {
  if (!qualifier || !qualifier.evidence || typeof qualifier.evidence !== 'object') return;
  const evidence = qualifier.evidence;
  if (!exactKeys(evidence, QUALIFIER_EVIDENCE_KEYS)) {
    add('holder_finding_evidence_invalid');
    return;
  }
  const adjusted = qualifier.code === 'holders.adjusted_for_known_venues';
  if (adjusted) {
    if (evidence.adjustedForKnownVenues !== true || !isNonEmptyString(evidence.exclusionEvidence) ||
        !isPositiveSafeInteger(evidence.excludedCount)) add('holder_finding_evidence_invalid');
  } else if (evidence.adjustedForKnownVenues !== false || evidence.exclusionEvidence !== null ||
      evidence.excludedCount !== 0) {
    add('holder_finding_evidence_invalid');
  }
  if (primary && primary.evidence) {
    const metrics = primary.evidence.metrics;
    if (evidence.adjustedForKnownVenues !== primary.evidence.adjustedForKnownVenues ||
        evidence.exclusionEvidence !== primary.evidence.exclusionEvidence ||
        !metrics || evidence.excludedCount !== metrics.excludedCount) {
      add('holder_finding_evidence_invalid');
    }
  }
}

function validateVenueFinding(finding, add) {
  if (!finding || !finding.evidence || typeof finding.evidence !== 'object') return;
  const evidence = finding.evidence;
  const expectedComplete = finding.code === 'venue.pumpfun_curve_complete';
  if (!exactKeys(evidence, VENUE_EVIDENCE_KEYS) ||
      evidence.venue !== 'pumpfun_bonding_curve' ||
      !isSolanaAddress(evidence.curveAddress) ||
      evidence.complete !== expectedComplete ||
      !isNullOrDigitString(evidence.realTokenReservesRaw) ||
      !isNullOrDigitString(evidence.realSolReservesRaw)) {
    add('holder_finding_evidence_invalid');
  }
}

function validateReadSlots(readSlots, attempt, input, add) {
  if (!readSlots || !exactKeys(readSlots, [
    'mint', 'metadata', 'largestAccounts', 'supply', 'venueCustody', 'liquidity',
  ])) {
    add('producer_context_invalid');
    return;
  }
  const validSlot = (slot) => slot === null || isPositiveSafeInteger(slot);
  const validSurface = (surface) => surface && exactKeys(surface, ['attempted', 'loadBearing', 'slots']) &&
    typeof surface.attempted === 'boolean' && typeof surface.loadBearing === 'boolean' &&
    Array.isArray(surface.slots) && surface.slots.every(validSlot) &&
    (surface.attempted ? surface.slots.length > 0 : surface.slots.length === 0) &&
    (!surface.loadBearing || surface.attempted);
  if (!validSlot(readSlots.mint) || !validSlot(readSlots.metadata) ||
      !validSlot(readSlots.largestAccounts) || !validSlot(readSlots.supply) ||
      !validSurface(readSlots.venueCustody) || !validSurface(readSlots.liquidity)) {
    add('producer_context_invalid');
    return;
  }
  if (!isPositiveSafeInteger(input.observedSlot)) {
    add('producer_context_invalid');
  }
  const slotTerminal = attempt && attempt.state === 'attempted_unavailable' &&
    ['holder_observation_slot_missing', 'holder_observation_slot_mismatch'].includes(attempt.reason);
  if (!slotTerminal && readSlots.mint !== input.observedSlot) {
    add('holder_observation_slot_mismatch');
  }
  if (input.metadataEvaluated !== true && readSlots.metadata !== null) {
    add('holder_metadata_context_mismatch');
  }
  if (!slotTerminal && input.metadataEvaluated === true && readSlots.metadata !== input.observedSlot) {
    add('holder_observation_slot_mismatch');
  }
  const checks = attempt && Array.isArray(attempt.attemptedChecks) ? attempt.attemptedChecks : [];
  if (readSlots.venueCustody.attempted !== checks.includes('venue_custody') ||
      readSlots.liquidity.attempted !== checks.includes('liquidity_coherence')) {
    add('holder_attempt_expectation_mismatch');
  }
  if (!checks.includes('token_supply') && readSlots.supply !== null) {
    add('holder_attempt_expectation_mismatch');
  }
  if (attempt && attempt.reason === 'holder_fetch_failed' &&
      readSlots.largestAccounts !== null) {
    add('holder_attempt_expectation_mismatch');
  }
  const loadBearingSlots = [readSlots.mint, readSlots.largestAccounts, readSlots.supply];
  if (input.metadataEvaluated === true) loadBearingSlots.push(readSlots.metadata);
  if (readSlots.venueCustody.loadBearing) loadBearingSlots.push(...readSlots.venueCustody.slots);
  if (readSlots.liquidity.loadBearing) loadBearingSlots.push(...readSlots.liquidity.slots);
  const hasMissing = loadBearingSlots.some((slot) => slot === null);
  const present = loadBearingSlots.filter((slot) => slot !== null);
  const hasMismatch = !hasMissing && new Set(present).size > 1;
  if (attempt && attempt.state === 'attempted_unavailable') {
    if (attempt.reason === 'holder_observation_slot_missing' && !hasMissing) {
      add('holder_attempt_expectation_mismatch');
    }
    if (attempt.reason === 'holder_observation_slot_mismatch' && (hasMissing || !hasMismatch)) {
      add('holder_attempt_expectation_mismatch');
    }
    if (!['holder_observation_slot_missing', 'holder_observation_slot_mismatch'].includes(attempt.reason) &&
        attempt.observation !== null && (hasMissing || hasMismatch)) {
      add('holder_attempt_expectation_mismatch');
    }
  }
  if (attempt && attempt.observation) {
    const observation = typeof attempt.observation === 'object'
      ? attempt.observation
      : null;
    const contexts = observation && observation.contexts;
    if (readSlots.mint !== input.observedSlot || readSlots.largestAccounts !== input.observedSlot ||
        readSlots.supply !== input.observedSlot ||
        (input.metadataEvaluated === true && readSlots.metadata !== input.observedSlot) ||
        (readSlots.venueCustody.loadBearing && readSlots.venueCustody.slots.some((slot) => slot !== input.observedSlot)) ||
        (readSlots.liquidity.loadBearing && readSlots.liquidity.slots.some((slot) => slot !== input.observedSlot))) {
      add('holder_observation_slot_mismatch');
    }
    if (contexts !== null && contexts !== undefined) {
      if (contexts.metadata !== (input.metadataEvaluated === true)) add('holder_metadata_context_mismatch');
      if (contexts.venueCustody !== readSlots.venueCustody.loadBearing) add('holder_venue_context_mismatch');
      if (contexts.liquidity !== readSlots.liquidity.loadBearing) add('holder_liquidity_context_mismatch');
    }
  }
}

function validateHolderAdmission(rawInput) {
  const input = rawInput && typeof rawInput === 'object' ? rawInput : {};
  const rulesVersion = input.rulesVersion;
  if (typeof rulesVersion !== 'string' || !/^raven-rules@[0-9]+\.[0-9]+\.[0-9]+$/.test(rulesVersion)) {
    return {
      ok: false,
      errorCode: 'malformed_rules_version',
      reasons: ['malformed_rules_version'],
      rulesStatus: 'malformed',
    };
  }
  if (HISTORICAL_RULES_VERSIONS.has(rulesVersion)) {
    return {
      ok: true,
      state: 'historical',
      holderAttempt: null,
      rulesStatus: 'supported_valid',
      producerDisposition: 'not_applicable',
      reasons: [],
    };
  }
  if (rulesVersion !== RULES_VERSION_1_1_4) {
    return {
      ok: false,
      errorCode: 'unsupported_rules_version',
      reasons: ['unsupported_rules_version'],
      rulesStatus: 'unsupported',
    };
  }

  const foundReasons = new Set();
  const add = (reason) => foundReasons.add(reason);
  const mode = validateMode(input.mode, add);
  if (mode.kind === 'producer' && typeof input.metadataEvaluated !== 'boolean') {
    add('producer_context_invalid');
  }
  if (mode.kind === 'producer' && mode.execution === 'not_started') {
    return {
      ok: false,
      errorCode: 'holder_attempt_not_executed',
      reasons: ['holder_attempt_not_executed'],
      rulesStatus: 'supported_invalid',
    };
  }
  if (mode.kind === 'producer' && mode.execution === 'started_uncompleted') {
    return {
      ok: false,
      errorCode: 'holder_attempt_not_completed',
      reasons: ['holder_attempt_not_completed'],
      rulesStatus: 'supported_invalid',
    };
  }

  const findingsSnapshot = snapshotAdmissionFindings(input.findings);
  if (!findingsSnapshot.ok) {
    add(findingsSnapshot.holderAttempt
      ? 'holder_attempt_unexpected'
      : 'holder_finding_shape_invalid');
    return {
      ok: false,
      errorCode: 'holder_provenance_invalid',
      reasons: REASON_ORDER.filter((reason) => foundReasons.has(reason)),
      rulesStatus: 'supported_invalid',
    };
  }
  const findings = findingsSnapshot.value;
  if (!Array.isArray(input.findings)) add('holder_finding_shape_invalid');
  const projectedFindingCodes = findings.map((finding) => finding && finding.code);
  if (input.findingCodes !== undefined) {
    if (!exactArray(input.findingCodes, projectedFindingCodes)) add('finding_codes_mismatch');
  }
  const hasPublishedOutcomeProjection = input.outcome !== undefined ||
    input.outcomeReason !== undefined || input.triggeringFindingCodes !== undefined;
  if (mode.kind === 'producer' || hasPublishedOutcomeProjection) {
    const expectedProjection = classifyFindingEnvelopeOutcome({ findings });
    if (expectedProjection.ok !== true || input.outcome !== expectedProjection.value.outcome ||
        input.outcomeReason !== expectedProjection.value.reason) {
      add('holder_state_contradiction');
    }
    if (expectedProjection.ok !== true ||
        !exactArray(input.triggeringFindingCodes, expectedProjection.value.triggeringFindingCodes)) {
      add('finding_codes_mismatch');
    }
  }
  const holderFindings = findings.filter(
    (finding) => finding && HOLDER_DERIVED_CODES.has(finding.code),
  );
  if (findingsSnapshot.unexpectedHolderAttempt) {
    add('holder_attempt_unexpected');
  }
  const primary = holderFindings.filter((finding) => PRIMARY_CODES.has(finding.code));
  const affirmative = primary.filter((finding) => AFFIRMATIVE_CODES.has(finding.code));
  const unresolved = primary.filter((finding) => finding.code === 'holders.distribution_unresolved');
  const qualifiers = holderFindings.filter((finding) => QUALIFIER_CODES.has(finding.code));
  const venues = holderFindings.filter((finding) => VENUE_CODES.has(finding.code));

  let state = 'not_requested';
  if (unresolved.length > 0) state = 'attempted_unavailable';
  if (affirmative.length > 0) state = 'observed';
  if (primary.length > 1 || (unresolved.length > 0 && affirmative.length > 0)) {
    add('holder_primary_cardinality_invalid');
    add('holder_state_contradiction');
  }
  if (state === 'not_requested' && (qualifiers.length > 0 || venues.length > 0)) {
    add('holder_primary_cardinality_invalid');
    add('holder_state_contradiction');
  }
  if (state === 'attempted_unavailable' && (unresolved.length !== 1 || qualifiers.length !== 0 || venues.length !== 0)) {
    add('holder_state_contradiction');
    if (qualifiers.length !== 0) add('holder_qualifier_cardinality_invalid');
    if (venues.length !== 0) add('holder_venue_state_contradiction');
  }
  if (state === 'observed') {
    if (affirmative.length !== 1) add('holder_primary_cardinality_invalid');
    if (qualifiers.length !== 1) add('holder_qualifier_cardinality_invalid');
    if (venues.length > 1) add('holder_venue_state_contradiction');
  }

  if (mode.kind === 'producer' && mode.selection === 'not_selected' && holderFindings.length > 0) {
    add('holder_not_selected_but_present');
  }
  if (mode.kind === 'producer' && mode.selection !== 'not_selected' &&
      mode.execution === 'completed' && state === 'not_requested') {
    add('holder_state_contradiction');
  }

  const attempts = [];
  let missingAttempt = false;
  for (const finding of holderFindings) {
    if (!exactKeys(finding, ['code', 'source', 'subject', 'evidence'])) {
      add('holder_finding_shape_invalid');
    }
    if (finding.source !== HOLDER_FINDING_SOURCE) add('holder_finding_source_invalid');
    const expectedSubject = PRIMARY_CODES.has(finding.code)
      ? 'holder_concentration'
      : QUALIFIER_CODES.has(finding.code)
        ? 'holder_concentration_basis'
        : 'venue_custody_state';
    if (finding.subject !== expectedSubject) add('holder_finding_subject_invalid');
    const evidenceKeys = PRIMARY_CODES.has(finding.code)
      ? PRIMARY_EVIDENCE_KEYS
      : QUALIFIER_CODES.has(finding.code)
        ? QUALIFIER_EVIDENCE_KEYS
        : VENUE_EVIDENCE_KEYS;
    if (!finding.evidence || !exactKeys(finding.evidence, evidenceKeys)) {
      add('holder_finding_evidence_invalid');
    }
    const attemptPresent = Boolean(
      finding.evidence &&
      Object.prototype.hasOwnProperty.call(finding.evidence, 'holderAttempt'),
    );
    const attempt = attemptPresent ? finding.evidence.holderAttempt : undefined;
    validateAttempt(attempt, input, add, attemptPresent);
    if (!attemptPresent) missingAttempt = true;
    if (attempt && typeof attempt === 'object' && !Array.isArray(attempt)) attempts.push(attempt);
  }
  if (missingAttempt) add('holder_attempt_missing');
  if (attempts.length > 1) {
    if (attempts.some((attempt) => !boundedStructuralEqual(attempts[0], attempt))) {
      add('holder_attempt_copy_mismatch');
    }
  }
  const attempt = attempts[0] || null;
  if (attempt &&
      ((state === 'attempted_unavailable' && attempt.state !== 'attempted_unavailable') ||
       (state === 'observed' && attempt.state !== 'observed'))) {
    add('holder_state_contradiction');
  }

  if (primary[0]) validatePrimary(primary[0], add);
  if (qualifiers[0]) validateQualifier(qualifiers[0], primary[0], add);
  for (const venue of venues) validateVenueFinding(venue, add);

  if (attempt && Array.isArray(attempt.attemptedChecks)) {
    const checks = attempt.attemptedChecks;
    const hasVenueCheck = checks.includes('venue_custody');
    const hasLiquidityCheck = checks.includes('liquidity_coherence');
    if (attempt.state === 'observed' && !exactArray(checks.slice(0, 2), ['largest_accounts', 'token_supply'])) {
      add('holder_attempt_checks_invalid');
    }
    if (attempt.state === 'attempted_unavailable') {
      if (['holder_fetch_failed', 'holder_decode_failed'].includes(attempt.reason) &&
          !exactArray(checks, ['largest_accounts'])) add('holder_attempt_checks_invalid');
      if (attempt.reason === 'supply_fetch_failed' &&
          !exactArray(checks, ['largest_accounts', 'token_supply'])) add('holder_attempt_checks_invalid');
      if (!['holder_fetch_failed', 'holder_decode_failed'].includes(attempt.reason) &&
          !exactArray(checks.slice(0, 2), ['largest_accounts', 'token_supply'])) {
        add('holder_attempt_checks_invalid');
      }
      if (['zero_total_supply', 'no_holder_accounts_returned', 'holder_amounts_exceed_supply'].includes(attempt.reason) &&
          hasVenueCheck) add('holder_attempt_checks_invalid');
      if (attempt.reason === 'all_accounts_excluded' && !hasVenueCheck) add('holder_attempt_checks_invalid');
    }
    const contexts = attempt.observation && attempt.observation.contexts;
    const adjusted = qualifiers[0] && qualifiers[0].code === 'holders.adjusted_for_known_venues';
    if ((adjusted || venues.length > 0) && (!hasVenueCheck || !contexts || contexts.venueCustody !== true)) {
      add('holder_venue_context_mismatch');
    }
    if (qualifiers[0] && qualifiers[0].code === 'holders.unadjusted_may_include_pools' &&
        contexts && contexts.venueCustody !== false) add('holder_venue_context_mismatch');
    if (attempt.reason === 'all_accounts_excluded' &&
        (!contexts || contexts.venueCustody !== true || !hasVenueCheck)) {
      add('holder_venue_context_mismatch');
    }
    if (['zero_total_supply', 'no_holder_accounts_returned', 'holder_amounts_exceed_supply'].includes(attempt.reason) &&
        contexts && contexts.venueCustody !== false) add('holder_venue_context_mismatch');
    const hasLiquidityFinding = findings.some((finding) => finding && LIQUIDITY_CODES.has(finding.code));
    if (hasLiquidityFinding && (!hasLiquidityCheck || !contexts || contexts.liquidity !== true)) {
      add('holder_liquidity_context_mismatch');
    }
    if (!hasLiquidityFinding && contexts && contexts.liquidity !== false) {
      add('holder_liquidity_context_mismatch');
    }
    const metadataLoadBearing =
      (Array.isArray(input.scopeChecksPerformed) && input.scopeChecksPerformed.includes('metadata_mutability')) ||
      findings.some((finding) => finding && finding.code === 'issuer_control.metadata_mutable' &&
        finding.subject === 'metadata_mutability');
    if (contexts && contexts.metadata !== metadataLoadBearing) add('holder_metadata_context_mismatch');
    if (typeof input.metadataEvaluated === 'boolean' && contexts &&
        contexts.metadata !== input.metadataEvaluated) add('holder_metadata_context_mismatch');
  }

  const coverageGaps = Array.isArray(input.coverageGaps) ? input.coverageGaps : [];
  if (!arrayOfUniqueStrings(coverageGaps)) add('holder_coverage_gap_invalid');
  const hasTopGap = coverageGaps.includes('top_holders');
  const hasVenueGap = coverageGaps.includes('holder_venue_adjustment');
  if ((state === 'not_requested' || state === 'attempted_unavailable') && !hasTopGap) {
    add('holder_coverage_gap_invalid');
  }
  if (state === 'attempted_unavailable' && coverageGaps.length === 0) {
    add('holder_coverage_gap_invalid');
  }
  if (state === 'observed' && hasTopGap) add('holder_coverage_gap_invalid');
  const allExcluded = state === 'attempted_unavailable' && attempt && attempt.reason === 'all_accounts_excluded';
  const adjustedObserved = state === 'observed' && qualifiers[0] &&
    qualifiers[0].code === 'holders.adjusted_for_known_venues';
  if ((allExcluded || adjustedObserved) && hasVenueGap) add('holder_coverage_gap_invalid');
  if (((state === 'attempted_unavailable' && !allExcluded) ||
      (state === 'observed' && !adjustedObserved)) && !hasVenueGap) {
    add('holder_coverage_gap_invalid');
  }

  if (input.scopeChecksPerformed !== undefined || input.scopeChecksNotPerformed !== undefined) {
    const performed = input.scopeChecksPerformed;
    const notPerformed = input.scopeChecksNotPerformed;
    if (!arrayOfUniqueStrings(performed) || !arrayOfUniqueStrings(notPerformed) ||
        performed.some((check) => notPerformed.includes(check))) {
      add('holder_scope_checks_invalid');
    } else if (state === 'observed') {
      if (!performed.includes('top_holders') || notPerformed.includes('top_holders')) {
        add('holder_scope_checks_invalid');
      }
    } else if (performed.includes('top_holders') || !notPerformed.includes('top_holders')) {
      add('holder_scope_checks_invalid');
    }
    if (arrayOfUniqueStrings(performed) && arrayOfUniqueStrings(notPerformed)) {
      const metadataFinding = findings.some((finding) =>
        finding && finding.code === 'issuer_control.metadata_mutable' &&
        finding.subject === 'metadata_mutability');
      if (metadataFinding &&
          (!performed.includes('metadata_mutability') || notPerformed.includes('metadata_mutability'))) {
        add('holder_scope_checks_invalid');
      }
    }
  }

  if (mode.kind === 'producer' && mode.execution === 'completed') {
    const acquisition = mode.acquisition;
    if (!acquisition || !acquisition.attempt || !attempt ||
        !boundedStructuralEqual(acquisition.attempt, attempt)) {
      add('holder_attempt_expectation_mismatch');
    }
    const primaryEvidence = primary[0] && primary[0].evidence;
    const expectedClassification = primaryEvidence && typeof primaryEvidence === 'object'
      ? {
          classification: primaryEvidence.classification,
          reason: primaryEvidence.reason,
          classifierVersion: primaryEvidence.classifierVersion,
          adjustedForKnownVenues: primaryEvidence.adjustedForKnownVenues === true,
          exclusionEvidence:
            typeof primaryEvidence.exclusionEvidence === 'string'
              ? primaryEvidence.exclusionEvidence
              : null,
          metrics: primaryEvidence.metrics,
        }
      : null;
    if (!acquisition || !acquisition.classification || !primary[0] ||
        !boundedStructuralEqual(expectedClassification, acquisition.classification)) {
      add('holder_classifier_expectation_mismatch');
    }
    if (acquisition) validateReadSlots(acquisition.readSlots, acquisition.attempt, input, add);
  }

  const reasons = REASON_ORDER.filter((reason) => foundReasons.has(reason));
  if (reasons.length > 0) {
    return {
      ok: false,
      errorCode: 'holder_provenance_invalid',
      reasons,
      rulesStatus: 'supported_invalid',
    };
  }
  return {
    ok: true,
    state,
    holderAttempt: attempt,
    rulesStatus: 'supported_valid',
    producerDisposition:
      mode.kind === 'producer'
        ? state === 'attempted_unavailable' && mode.selection === 'mandatory'
          ? 'refuse_holder_evidence_unavailable'
          : 'admit'
        : 'not_applicable',
    reasons: [],
  };
}

module.exports = {
  HISTORICAL_RULES_VERSIONS,
  HOLDER_DERIVED_CODES,
  LIQUIDITY_CODES,
  REASON_ORDER,
  validateHolderAdmission,
};
