// Canonical Solana finding outcome projection used by the 1.1.4 admission
// parity corpus. Receipt-v1 does not sign these three fields, so this helper is
// additive interpretation support; receipt acceptance never infers them.

export type SolanaOutcome =
  | "pass"
  | "pass_with_info_finding"
  | "warning"
  | "risk";

export interface FindingOutcomeProjection {
  outcome: SolanaOutcome;
  reason: string;
  triggeringFindingCodes: string[];
}

export type FindingOutcomeProjectionResult =
  | { ok: true; value: FindingOutcomeProjection }
  | { ok: false; errorCode: "invalid_finding_codes" | "finding_missing_code" };

const RISK = new Set([
  "issuer_control.mint_authority_active",
  "issuer_control.freeze_authority_active",
  "issuer_control.permanent_delegate_active",
  "issuer_control.transfer_hook_present",
  "issuer_control.metadata_mutable",
  "issuer_control.transfer_fee_config_present",
  "issuer_control.mint_close_authority_active",
  "issuer_control.default_account_state_frozen",
  "issuer_control.pausable_present",
  "venue.liquidity_withdrawable",
]);
const WARNING = new Set([
  "venue.infrastructure_tier_mutable",
  "venue.infrastructure_tier_unresolved",
  "venue.liquidity_unresolved",
]);
const TOKEN_2022_WARNING = new Set([
  "token2022.unknown_extension_present",
  "token2022.non_transferable_present",
  "token2022.scaled_ui_amount_present",
]);
const HOLDER_WARNING = new Set([
  "holders.concentration_high",
  "holders.distribution_unresolved",
]);
const LIQUIDITY_DEPTH_WARNING = new Set([
  "liquidity.supply_majority_returned_to_pool",
]);
const INFO = new Set([
  "venue.infrastructure_tier_mutable_but_known",
  "venue.liquidity_partially_locked",
]);
const TOKEN_2022_INFO = new Set([
  "token2022.metadata_pointer_present",
  "token2022.default_account_state_initialized",
  "token2022.mint_close_authority_inactive",
  "token2022.pausable_inactive",
  "token2022.interest_bearing_present",
  "token2022.confidential_transfer_present",
  "token2022.confidential_transfer_fee_present",
  "token2022.token_metadata_present",
  "token2022.group_pointer_present",
  "token2022.group_member_pointer_present",
]);
const HOLDER_INFO = new Set([
  "holders.concentration_moderate",
  "holders.distributed",
  "holders.adjusted_for_known_venues",
  "holders.unadjusted_may_include_pools",
]);
const VENUE_INFO = new Set([
  "venue.pumpfun_curve_active",
  "venue.pumpfun_curve_complete",
]);
const PASS = new Set([
  "venue.infrastructure_tier_immutable",
  "venue.liquidity_locked",
]);

const collect = (codes: readonly string[], members: ReadonlySet<string>): string[] => {
  const found: string[] = [];
  const seen = new Set<string>();
  for (const code of codes) {
    if (members.has(code) && !seen.has(code)) {
      seen.add(code);
      found.push(code);
    }
  }
  return found;
};

/** Exact independent port of raven-solana-outcome's precedence table. */
export const classifyFindingCodesOutcome = (
  rawCodes: unknown,
): FindingOutcomeProjectionResult => {
  if (!Array.isArray(rawCodes)) return { ok: false, errorCode: "invalid_finding_codes" };
  if (!rawCodes.every((code) => typeof code === "string" && code.length > 0)) {
    return { ok: false, errorCode: "finding_missing_code" };
  }
  const codes = rawCodes as string[];
  const success = (
    outcome: SolanaOutcome,
    reason: string,
    triggeringFindingCodes: string[],
  ): FindingOutcomeProjectionResult => ({
    ok: true,
    value: { outcome, reason, triggeringFindingCodes },
  });
  if (codes.length === 0) return success("warning", "no_deterministic_findings", []);

  for (const [members, outcome, reason] of [
    [RISK, "risk", "issuer_control_finding_present"],
    [WARNING, "warning", "mutable_or_unresolved_infrastructure"],
    [TOKEN_2022_WARNING, "warning", "token2022_extension_warning_present"],
    [HOLDER_WARNING, "warning", "holder_concentration_warning"],
    [LIQUIDITY_DEPTH_WARNING, "warning", "liquidity_supply_returned_to_pool_warning"],
    [INFO, "pass_with_info_finding", "mutable_but_known_infrastructure_dependency"],
    [TOKEN_2022_INFO, "pass_with_info_finding", "token2022_informational_extension_present"],
    [HOLDER_INFO, "pass_with_info_finding", "holder_distribution_informational"],
    [VENUE_INFO, "pass_with_info_finding", "venue_custody_informational"],
    [PASS, "pass", "immutable_infrastructure_only"],
  ] as const) {
    const triggers = collect(codes, members);
    if (triggers.length > 0) return success(outcome, reason, triggers);
  }
  return success("warning", "no_deterministic_findings", []);
};
