// README trust-contract checker. Binds each PROPOSITION a sentence teaches to
// the reason code it names, so the doc cannot drift from the shipped verifier:
//   omitted trust policy               → trust_config_missing
//   present-but-malformed trust policy → trust_config_invalid
//   non-Ed25519 TRUSTED-KEY material   → trust_config_invalid
//   non-Ed25519 receipt SIGNER         → trust_key_type_unsupported
// A unit (sentence or table row) that names a proposition and at least one
// reason code must name the proposition's correct code; a unit with exactly one
// proposition and exactly one code must pair them. Units without a code are not
// checked (they teach nothing about codes).

export const CONTRACT = {
  omission: "trust_config_missing",
  malformed: "trust_config_invalid",
  pinMaterial: "trust_config_invalid",
  signer: "trust_key_type_unsupported",
} as const;
export type Proposition = keyof typeof CONTRACT;

const CODE_RE = /\b(trust_config_missing|trust_config_invalid|trust_key_type_unsupported|key_untrusted|key_trust_not_evaluated)\b/g;
const OMISSION_RE = /\bomit(?:s|ted|ting)?\b|\bomission\b|\bmissing trust\b|\btrust (?:policy|config(?:uration)?) (?:is |was )?(?:absent|missing|omitted)\b/i;
const MALFORMED_RE = /\bmalformed\b/i;
const NON_ED_RE = /non-?Ed25519|another algorithm|other algorithm|\bP-?256\b|\bRSA\b|\bnot (?:an? )?Ed25519\b|unsupported (?:key|pin|signer|trusted-key|algorithm)/i;
const SIGNER_RE = /\bsigner\b|signerPublicKey|signed by/i;

export const propositionsOf = (unit: string): Proposition[] => {
  const out: Proposition[] = [];
  if (OMISSION_RE.test(unit)) out.push("omission");
  if (MALFORMED_RE.test(unit)) out.push("malformed");
  if (NON_ED_RE.test(unit)) out.push(SIGNER_RE.test(unit) ? "signer" : "pinMaterial");
  return out;
};
export const codesOf = (unit: string): string[] => Array.from(new Set(unit.match(CODE_RE) ?? []));

/** Split README text into checkable units: table rows stay whole; prose splits on sentence ends and semicolons. */
export const unitsOf = (text: string): string[] => {
  const units: string[] = [];
  let prose: string[] = [];
  const flush = () => {
    if (prose.length === 0) return;
    const para = prose.join(" ").replace(/\s+/g, " ").trim();
    prose = [];
    for (const s of para.split(/(?<=[.!?])\s+(?=[A-Z`*(\d])|;\s+/)) if (s.trim()) units.push(s.trim());
  };
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (line.startsWith("|")) { flush(); if (!/^\|[\s:|-]+\|$/.test(line)) units.push(line); continue; }
    if (line === "" || line.startsWith("#") || line.startsWith("```")) { flush(); continue; }
    prose.push(line);
  }
  flush();
  return units;
};

export interface Contradiction { unit: string; proposition: Proposition; expected: string; found: string[] }

export const contradictionsIn = (text: string): Contradiction[] => {
  const out: Contradiction[] = [];
  for (const unit of unitsOf(text)) {
    const codes = codesOf(unit);
    if (codes.length === 0) continue;
    const props = propositionsOf(unit);
    for (const p of props) {
      const expected = CONTRACT[p];
      if (!codes.includes(expected)) out.push({ unit, proposition: p, expected, found: codes });
      else if (props.length === 1 && codes.length === 1 && codes[0] !== expected) out.push({ unit, proposition: p, expected, found: codes });
    }
  }
  return out;
};

/** The canonical contract table every shipped verifier README must carry (one proposition, one code per row). */
export const REQUIRED_ROWS: Array<[Proposition, RegExp]> = [
  ["omission", /^\|\s*omitted trust policy\b.*\|\s*`trust_config_missing`\s*\|$/i],
  ["malformed", /^\|\s*present but malformed trust policy\b.*\|\s*`trust_config_invalid`\s*\|$/i],
  ["pinMaterial", /^\|\s*unsupported \(non-Ed25519\) trusted-key material\b.*\|\s*`trust_config_invalid`\s*\|$/i],
  ["signer", /^\|\s*unsupported \(non-Ed25519\) receipt signer\b.*\|\s*`trust_key_type_unsupported`\s*\|$/i],
];
export const missingRows = (text: string): Proposition[] => {
  const units = unitsOf(text);
  return REQUIRED_ROWS.filter(([, re]) => !units.some((u) => re.test(u))).map(([p]) => p);
};
