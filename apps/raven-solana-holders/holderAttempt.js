'use strict';

const RULES_VERSION_1_1_4 = 'raven-rules@1.1.4';
const HOLDER_ATTEMPT_VERSION = 'raven-holder-attempt/v1';
const HOLDER_FINDING_SOURCE = 'holder_distribution_evidence';

const HOLDER_ATTEMPT_CHECKS = Object.freeze([
  'largest_accounts',
  'token_supply',
  'venue_custody',
  'liquidity_coherence',
]);

const HOLDER_UNAVAILABLE_REASONS = Object.freeze([
  'holder_fetch_failed',
  'holder_decode_failed',
  'supply_fetch_failed',
  'holder_observation_slot_missing',
  'holder_observation_slot_mismatch',
  'zero_total_supply',
  'no_holder_accounts_returned',
  'holder_amounts_exceed_supply',
  'all_accounts_excluded',
]);

const HOLDER_CLASSIFICATIONS_V1 = Object.freeze([
  'high_concentration',
  'moderate_concentration',
  'distributed',
  'unresolved',
]);

const COMMITMENTS = Object.freeze(['finalized', 'confirmed', 'processed']);

function deepFreeze(value) {
  if (!value || typeof value !== 'object' || Object.isFrozen(value)) return value;
  for (const nested of Object.values(value)) deepFreeze(nested);
  return Object.freeze(value);
}

function cloneJsonValue(value) {
  if (Array.isArray(value)) return value.map(cloneJsonValue);
  if (value && typeof value === 'object') {
    const clone = {};
    for (const [key, nested] of Object.entries(value)) clone[key] = cloneJsonValue(nested);
    return clone;
  }
  return value;
}

function canonicalJson(value) {
  const ancestors = new Set();
  function encode(current) {
    if (current === null) return 'null';
    if (typeof current === 'bigint') return JSON.stringify(`~bigint:${current.toString()}`);
    if (typeof current === 'undefined') return '"~undefined"';
    if (typeof current === 'function') return '"~function"';
    if (typeof current === 'symbol') return JSON.stringify(`~symbol:${String(current.description || '')}`);
    if (typeof current !== 'object') return JSON.stringify(current);
    if (ancestors.has(current)) return '"~circular"';
    ancestors.add(current);
    let encoded;
    if (Array.isArray(current)) {
      encoded = `[${current.map(encode).join(',')}]`;
    } else {
      encoded = `{${Object.keys(current)
        .sort()
        .map((key) => `${JSON.stringify(key)}:${encode(current[key])}`)
        .join(',')}}`;
    }
    ancestors.delete(current);
    return encoded;
  }
  return encode(value);
}

function exactKeys(value, keys) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const actual = Object.keys(value).sort();
  const expected = keys.slice().sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isPositiveSafeInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function isDigitString(value) {
  return typeof value === 'string' && /^[0-9]+$/.test(value);
}

function decodeBase58Length(value) {
  if (typeof value !== 'string' || !/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(value)) {
    return null;
  }
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let decoded = 0n;
  for (const character of value) {
    const digit = alphabet.indexOf(character);
    if (digit < 0) return null;
    decoded = decoded * 58n + BigInt(digit);
  }
  let byteLength = 0;
  let remaining = decoded;
  while (remaining > 0n) {
    byteLength += 1;
    remaining >>= 8n;
  }
  let leadingZeroes = 0;
  while (leadingZeroes < value.length && value[leadingZeroes] === '1') {
    leadingZeroes += 1;
  }
  return leadingZeroes + byteLength;
}

function isSolanaAddress(value) {
  return decodeBase58Length(value) === 32;
}

function buildHolderAttemptV1(input) {
  const request = input && typeof input === 'object' ? input : {};
  const observation = request.observation === null
    ? null
    : {
        slot: request.observation && request.observation.slot,
        contexts: {
          mint: request.observation && request.observation.contexts && request.observation.contexts.mint,
          metadata: request.observation && request.observation.contexts && request.observation.contexts.metadata,
          largestAccounts:
            request.observation && request.observation.contexts && request.observation.contexts.largestAccounts,
          supply: request.observation && request.observation.contexts && request.observation.contexts.supply,
          venueCustody:
            request.observation && request.observation.contexts && request.observation.contexts.venueCustody,
          liquidity:
            request.observation && request.observation.contexts && request.observation.contexts.liquidity,
        },
      };
  return deepFreeze({
    version: HOLDER_ATTEMPT_VERSION,
    state: request.state,
    source: 'solana_rpc',
    result: request.state === 'observed' ? 'observed' : 'unavailable',
    reason: request.state === 'observed' ? null : request.reason,
    mintAddress: request.mintAddress,
    commitment: request.commitment,
    attemptedChecks: Array.isArray(request.attemptedChecks)
      ? request.attemptedChecks.slice()
      : [],
    observation,
  });
}

function buildHolderClassifierProjectionV1(value) {
  const source = value && typeof value === 'object' ? value : {};
  return deepFreeze({
    classification: source.classification,
    reason: source.reason,
    classifierVersion: source.classifierVersion,
    adjustedForKnownVenues: source.adjustedForKnownVenues === true,
    exclusionEvidence:
      typeof source.exclusionEvidence === 'string' ? source.exclusionEvidence : null,
    metrics:
      source.metrics && typeof source.metrics === 'object'
        ? cloneJsonValue(source.metrics)
        : null,
  });
}

module.exports = {
  COMMITMENTS,
  HOLDER_ATTEMPT_CHECKS,
  HOLDER_ATTEMPT_VERSION,
  HOLDER_CLASSIFICATIONS_V1,
  HOLDER_FINDING_SOURCE,
  HOLDER_UNAVAILABLE_REASONS,
  RULES_VERSION_1_1_4,
  buildHolderAttemptV1,
  buildHolderClassifierProjectionV1,
  canonicalJson,
  cloneJsonValue,
  deepFreeze,
  exactKeys,
  isDigitString,
  isPositiveSafeInteger,
  isSolanaAddress,
};
