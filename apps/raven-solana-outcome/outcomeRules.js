'use strict';

const SOLANA_OUTCOME_VALUES = Object.freeze({
  PASS: 'pass',
  PASS_WITH_INFO_FINDING: 'pass_with_info_finding',
  WARNING: 'warning',
  RISK: 'risk',
});

const RISK_FINDING_CODES = new Set([
  'issuer_control.mint_authority_active',
  'issuer_control.freeze_authority_active',
  'issuer_control.permanent_delegate_active',
  'issuer_control.transfer_hook_present',
  'issuer_control.metadata_mutable',
  'issuer_control.transfer_fee_config_present',
  'issuer_control.mint_close_authority_active',
  'issuer_control.default_account_state_frozen',
  'issuer_control.pausable_present',
  'venue.liquidity_withdrawable',
]);

const WARNING_FINDING_CODES = new Set([
  'venue.infrastructure_tier_mutable',
  'venue.infrastructure_tier_unresolved',
  'venue.liquidity_unresolved',
]);

const TOKEN2022_WARNING_FINDING_CODES = new Set([
  'token2022.unknown_extension_present',
  'token2022.non_transferable_present',
  'token2022.scaled_ui_amount_present',
]);

const HOLDERS_WARNING_FINDING_CODES = new Set([
  'holders.concentration_high',
  'holders.distribution_unresolved',
]);

// L-DEPTH liquidity depth warning. The first liquidity finding meant to affect
// the verdict (toward WARNING). It fires when the large majority of token
// supply has been sold back into the AMM pool, consistent with holders having
// largely exited — a structural on-chain fact, not a price judgment. This is a
// DOWNGRADE-only direction: placed in the warning tier (alongside the other
// warning sets, ABOVE every pass/info tier), so it can move a verdict toward
// warning but never upgrade one. Pinned by liquidityDepthOutcome.test.js.
const LIQUIDITY_DEPTH_WARNING_FINDING_CODES = new Set([
  'liquidity.supply_majority_returned_to_pool',
]);

const HOLDERS_INFO_FINDING_CODES = new Set([
  'holders.concentration_moderate',
  // "Distributed" is informational by design: well-spread holders must never
  // upgrade a verdict toward pass while liquidity/deployer gaps remain.
  'holders.distributed',
  'holders.adjusted_for_known_venues',
  'holders.unadjusted_may_include_pools',
]);

// P3-3 venue-custody state evidence. Informational only — knowing the token
// sits on (or has left) the pump.fun bonding curve never makes it safer.
// Deliberately NOT in the PASS set and evaluated after holder info so it can
// never upgrade or re-order existing verdicts.
const VENUE_STATE_INFO_FINDING_CODES = new Set([
  'venue.pumpfun_curve_active',
  'venue.pumpfun_curve_complete',
]);

const PASS_WITH_INFO_FINDING_CODES = new Set([
  'venue.infrastructure_tier_mutable_but_known',
  'venue.liquidity_partially_locked',
]);

const TOKEN2022_INFO_FINDING_CODES = new Set([
  'token2022.metadata_pointer_present',
  'token2022.default_account_state_initialized',
  'token2022.mint_close_authority_inactive',
  'token2022.pausable_inactive',
  'token2022.interest_bearing_present',
  'token2022.confidential_transfer_present',
  'token2022.confidential_transfer_fee_present',
  'token2022.token_metadata_present',
  'token2022.group_pointer_present',
  'token2022.group_member_pointer_present',
]);

const PASS_FINDING_CODES = new Set([
  'venue.infrastructure_tier_immutable',
  'venue.liquidity_locked',
]);

function createFailure(errorCode, message) {
  return {
    ok: false,
    errorCode,
    message,
  };
}

function createSuccess(outcome, reason, triggeringFindingCodes) {
  return {
    ok: true,
    value: {
      outcome,
      reason,
      triggeringFindingCodes: triggeringFindingCodes.slice(),
    },
  };
}

function collectCodes(findings, predicate) {
  const codes = [];
  const seen = new Set();

  for (const finding of findings) {
    const code = finding.code;

    if (predicate(code) && !seen.has(code)) {
      seen.add(code);
      codes.push(code);
    }
  }

  return codes;
}

function normalizeFindingEnvelope(findingEnvelope) {
  if (!findingEnvelope || typeof findingEnvelope !== 'object') {
    return createFailure(
      'invalid_finding_envelope',
      'Finding envelope must be an object or envelope result.',
    );
  }

  if (Object.prototype.hasOwnProperty.call(findingEnvelope, 'ok')) {
    if (findingEnvelope.ok !== true) {
      return createFailure(
        'finding_envelope_not_ok',
        'Finding envelope result must be ok=true before outcome classification.',
      );
    }

    if (
      !findingEnvelope.value ||
      typeof findingEnvelope.value !== 'object' ||
      !Array.isArray(findingEnvelope.value.findings)
    ) {
      return createFailure(
        'invalid_finding_envelope',
        'Finding envelope result must contain value.findings.',
      );
    }

    return {
      ok: true,
      value: {
        envelopeKind: findingEnvelope.value.envelopeKind,
        findings: findingEnvelope.value.findings.slice(),
      },
    };
  }

  if (!Array.isArray(findingEnvelope.findings)) {
    return createFailure(
      'invalid_finding_envelope',
      'Finding envelope must include a findings array.',
    );
  }

  return {
    ok: true,
    value: {
      envelopeKind: findingEnvelope.envelopeKind,
      findings: findingEnvelope.findings.slice(),
    },
  };
}

/**
 * Deterministically maps a Solana finding envelope into an outcome class.
 *
 * @param {object} findingEnvelope
 * @returns {{ ok: true, value: { outcome: string, reason: string, triggeringFindingCodes: string[] } } | { ok: false, errorCode: string, message: string }}
 */
function classifyFindingEnvelopeOutcome(findingEnvelope) {
  const normalizedEnvelope = normalizeFindingEnvelope(findingEnvelope);

  if (normalizedEnvelope.ok !== true) {
    return normalizedEnvelope;
  }

  const findings = normalizedEnvelope.value.findings;

  for (const finding of findings) {
    if (
      !finding ||
      typeof finding !== 'object' ||
      typeof finding.code !== 'string' ||
      finding.code.length === 0
    ) {
      return createFailure(
        'finding_missing_code',
        'Each finding in the envelope must include a non-empty string code.',
      );
    }
  }

  if (findings.length === 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.WARNING,
      'no_deterministic_findings',
      [],
    );
  }

  const riskCodes = collectCodes(findings, (code) => RISK_FINDING_CODES.has(code));
  if (riskCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.RISK,
      'issuer_control_finding_present',
      riskCodes,
    );
  }

  const warningCodes = collectCodes(
    findings,
    (code) => WARNING_FINDING_CODES.has(code),
  );
  if (warningCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.WARNING,
      'mutable_or_unresolved_infrastructure',
      warningCodes,
    );
  }

  const token2022WarningCodes = collectCodes(
    findings,
    (code) => TOKEN2022_WARNING_FINDING_CODES.has(code),
  );
  if (token2022WarningCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.WARNING,
      'token2022_extension_warning_present',
      token2022WarningCodes,
    );
  }

  const holdersWarningCodes = collectCodes(
    findings,
    (code) => HOLDERS_WARNING_FINDING_CODES.has(code),
  );
  if (holdersWarningCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.WARNING,
      'holder_concentration_warning',
      holdersWarningCodes,
    );
  }

  const liquidityDepthWarningCodes = collectCodes(
    findings,
    (code) => LIQUIDITY_DEPTH_WARNING_FINDING_CODES.has(code),
  );
  if (liquidityDepthWarningCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.WARNING,
      'liquidity_supply_returned_to_pool_warning',
      liquidityDepthWarningCodes,
    );
  }

  const infoCodes = collectCodes(
    findings,
    (code) => PASS_WITH_INFO_FINDING_CODES.has(code),
  );
  if (infoCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.PASS_WITH_INFO_FINDING,
      'mutable_but_known_infrastructure_dependency',
      infoCodes,
    );
  }

  const token2022InfoCodes = collectCodes(
    findings,
    (code) => TOKEN2022_INFO_FINDING_CODES.has(code),
  );
  if (token2022InfoCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.PASS_WITH_INFO_FINDING,
      'token2022_informational_extension_present',
      token2022InfoCodes,
    );
  }

  const holdersInfoCodes = collectCodes(
    findings,
    (code) => HOLDERS_INFO_FINDING_CODES.has(code),
  );
  if (holdersInfoCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.PASS_WITH_INFO_FINDING,
      'holder_distribution_informational',
      holdersInfoCodes,
    );
  }

  const venueStateInfoCodes = collectCodes(
    findings,
    (code) => VENUE_STATE_INFO_FINDING_CODES.has(code),
  );
  if (venueStateInfoCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.PASS_WITH_INFO_FINDING,
      'venue_custody_informational',
      venueStateInfoCodes,
    );
  }

  const passCodes = collectCodes(findings, (code) => PASS_FINDING_CODES.has(code));
  if (passCodes.length > 0) {
    return createSuccess(
      SOLANA_OUTCOME_VALUES.PASS,
      'immutable_infrastructure_only',
      passCodes,
    );
  }

  return createSuccess(
    SOLANA_OUTCOME_VALUES.WARNING,
    'no_deterministic_findings',
    [],
  );
}

module.exports = {
  SOLANA_OUTCOME_VALUES,
  classifyFindingEnvelopeOutcome,
  normalizeFindingEnvelope,
};
