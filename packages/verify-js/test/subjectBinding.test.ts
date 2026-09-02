// Subject-binding contract for verifyReceiptV1ForSubject — the partner-facing
// entrypoint of raven-receipt-verifier.
//
// The receipt-v1 signer binds a THREE-field subject: chain, mintAddress and
// tokenProgramAddress. A partner that asked for mint M under program P must be
// able to prove the returned evidence is for exactly that tuple — a receipt
// for the right mint under a different program context is not the requested
// evidence. The subject axis is SEPARATE from integrity/trust/freshness/rules:
// a mismatch never relabels cryptography, and tampering never becomes a
// subject-only failure.
//
// Contract points pinned here:
//  - expected subject is a CLOSED JSON object: exactly the three own
//    string-keyed fields, both addresses canonical base58 encodings of exactly
//    32 decoded bytes, chain the frozen 0.1.0 literal "solana-mainnet" — any
//    other expected chain is expected_subject_invalid, never a well-formed
//    mismatch (future namespaces require a reviewed surface expansion);
//  - subjectMatches is boolean | null; subjectReasons are stable and ordered
//    chain → mint → program; subject reasons NEVER enter the integrity
//    `reasons` array;
//  - the trust policy is REQUIRED: omission or malformed policy yields
//    keyTrusted:false + trust_config_invalid, never an absent trust axis;
//  - hostile receipts, expected subjects and options (proxies, revoked
//    proxies, throwing getters) are contained — an outcome, never an
//    exception.

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
  verifyReceiptV1,
  verifyReceiptV1ForSubject,
} from "../src/index.ts";

const FIXTURES = fileURLToPath(new URL("../fixtures/receipt-v1/", import.meta.url));
const load = (name: string) => JSON.parse(fs.readFileSync(FIXTURES + name, "utf8"));

const validMinimal = load("valid-minimal.json");
const wrongKey = load("wrong-key.json"); // attacker Ed25519; signature self-consistent
const tamperedFinding = load("tampered-finding.json"); // integrity INVALID, subject intact

const GENUINE_KEY = "MCowBQYDK2VwAyEA0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc=";

// The fixture's signed subject tuple. The chain value is the signer's chain
// NAMESPACE string, compared exactly — today "solana-mainnet".
const CHAIN = validMinimal.input.chain as string; // "solana-mainnet"
const MINT = validMinimal.input.mintAddress as string; // wrapped SOL
const PROGRAM = validMinimal.input.tokenProgramAddress as string; // Token-2022

// A different, still well-formed subject: BONK under the legacy Token program.
const OTHER_MINT = "DezXAZ8z7PnrnRJjz3wXBoRgixCa6xjnB7YaB1pPB263";
const OTHER_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";

const goodSubject = () => ({
  chain: CHAIN,
  mintAddress: MINT,
  tokenProgramAddress: PROGRAM,
});

const trust = { trustedKeys: [GENUINE_KEY] as readonly string[] };

// --- exact match ---------------------------------------------------------

test("exact chain/mint/program match: subjectMatches true, all axes intact", () => {
  const r = verifyReceiptV1ForSubject(validMinimal.input, goodSubject(), {
    now: validMinimal.now,
    ...trust,
  });
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, true);
  assert.equal(r.stale, false);
  assert.equal(r.subjectMatches, true);
  assert.deepEqual(r.subjectReasons, []);
});

test("wrapper result is the kernel result plus the subject axis, nothing else", () => {
  const opts = { now: validMinimal.now as string, ...trust };
  const kernel = verifyReceiptV1(validMinimal.input, opts);
  const wrapped = verifyReceiptV1ForSubject(validMinimal.input, goodSubject(), opts);
  const { subjectMatches, subjectReasons, ...rest } = wrapped;
  assert.deepEqual(rest, kernel);
  void subjectMatches;
  void subjectReasons;
});

// --- valid-but-different fields ------------------------------------------

test("each different valid field fails only subject binding", () => {
  const cases: Array<[string, Record<string, string>, string[]]> = [
    ["mint", { ...goodSubject(), mintAddress: OTHER_MINT }, ["subject_mint_mismatch"]],
    [
      "program",
      { ...goodSubject(), tokenProgramAddress: OTHER_PROGRAM },
      ["subject_token_program_mismatch"],
    ],
  ];
  for (const [label, subject, reasons] of cases) {
    const r = verifyReceiptV1ForSubject(validMinimal.input, subject, {
      now: validMinimal.now,
      ...trust,
    });
    assert.equal(r.subjectMatches, false, label);
    assert.deepEqual(r.subjectReasons, reasons, label);
    // Integrity, trust and freshness are NOT relabeled by a subject mismatch.
    assert.equal(r.valid, true, label);
    assert.equal(r.keyTrusted, true, label);
    assert.equal(r.stale, false, label);
    assert.ok(!r.reasons.some((x) => x.startsWith("subject_")), label);
  }
});

// The expected chain is the frozen 0.1.0 literal "solana-mainnet": anything
// else is malformed caller input, not a well-formed chain mismatch. A chain
// MISMATCH is only reachable from the receipt side — a receipt signed under a
// different namespace — so that case tamper-proofs the receipt and integrity
// fails independently below.
test('expected chain other than the frozen "solana-mainnet" literal is malformed, not a mismatch', () => {
  for (const chain of ["solana", "solana-devnet", "ethereum-mainnet"]) {
    const r = verifyReceiptV1ForSubject(
      validMinimal.input,
      { ...goodSubject(), chain },
      { now: validMinimal.now, ...trust },
    );
    assert.equal(r.subjectMatches, null, chain);
    assert.deepEqual(r.subjectReasons, ["expected_subject_invalid"], chain);
    // The integrity kernel still ran; only the binding axis refused.
    assert.equal(r.valid, true, chain);
  }
});

test("receipt signed under another chain namespace: chain mismatch fails only binding", () => {
  const foreign = { ...validMinimal.input, chain: "solana-devnet" };
  const r = verifyReceiptV1ForSubject(foreign, goodSubject(), {
    now: validMinimal.now,
    ...trust,
  });
  assert.equal(r.subjectMatches, false);
  assert.deepEqual(r.subjectReasons, ["subject_chain_mismatch"]);
  // Integrity fails independently — tampering never becomes a subject-only
  // failure.
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("payload_hash_mismatch"));
});

test("combined mismatch reports every reason in stable chain/mint/program order", () => {
  // A receipt carrying a wholly different subject tuple: integrity fails
  // independently (payload hash), binding reports every mismatch in order.
  const foreign = {
    ...validMinimal.input,
    chain: "solana-devnet",
    mintAddress: OTHER_MINT,
    tokenProgramAddress: OTHER_PROGRAM,
  };
  const r = verifyReceiptV1ForSubject(foreign, goodSubject(), {
    now: validMinimal.now,
    ...trust,
  });
  assert.equal(r.subjectMatches, false);
  assert.deepEqual(r.subjectReasons, [
    "subject_chain_mismatch",
    "subject_mint_mismatch",
    "subject_token_program_mismatch",
  ]);
  assert.equal(r.valid, false);
});

// --- malformed expected subject ------------------------------------------

const MALFORMED_SUBJECTS: Array<[string, unknown]> = [
  ["null", null],
  ["string", "solana-mainnet"],
  ["array", [CHAIN, MINT, PROGRAM]],
  ["missing key", { chain: CHAIN, mintAddress: MINT }],
  ["extra key", { ...goodSubject(), extra: "x" }],
  ["non-string mint", { ...goodSubject(), mintAddress: 42 }],
  ["empty chain", { ...goodSubject(), chain: "" }],
  // "0" is not in the base58 alphabet.
  ["non-base58 mint", { ...goodSubject(), mintAddress: "0" + MINT.slice(1) }],
  // Leading zero byte + 32 bytes = 33 decoded bytes; not a public key.
  ["33-byte mint", { ...goodSubject(), mintAddress: "1" + MINT }],
  // Decodes well below 32 bytes.
  ["short program", { ...goodSubject(), tokenProgramAddress: "1111" }],
  [
    "symbol-keyed extra",
    Object.assign(goodSubject(), { [Symbol("s")]: 1 }),
  ],
  ["inherited-only field", Object.assign(Object.create({ chain: CHAIN }), {
    mintAddress: MINT,
    tokenProgramAddress: PROGRAM,
  })],
];

for (const [label, subject] of MALFORMED_SUBJECTS) {
  test(`malformed expected subject (${label}): null + expected_subject_invalid, no throw`, () => {
    let r;
    assert.doesNotThrow(() => {
      r = verifyReceiptV1ForSubject(validMinimal.input, subject, {
        now: validMinimal.now,
        ...trust,
      });
    });
    assert.equal(r!.subjectMatches, null, label);
    assert.deepEqual(r!.subjectReasons, ["expected_subject_invalid"], label);
    // The integrity kernel still ran; only the binding axis refused.
    assert.equal(r!.valid, true, label);
    assert.ok(!r!.reasons.some((x) => x.startsWith("subject_")), label);
  });
}

test("throwing getter on the expected subject is contained", () => {
  const hostile = { chain: CHAIN, tokenProgramAddress: PROGRAM };
  Object.defineProperty(hostile, "mintAddress", {
    enumerable: true,
    get() {
      throw new Error("hostile getter");
    },
  });
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1ForSubject(validMinimal.input, hostile, {
      now: validMinimal.now,
      ...trust,
    });
  });
  assert.equal(r!.subjectMatches, null);
  assert.deepEqual(r!.subjectReasons, ["expected_subject_invalid"]);
});

test("revoked-Proxy expected subject is contained", () => {
  const { proxy, revoke } = Proxy.revocable(goodSubject(), {});
  revoke();
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1ForSubject(validMinimal.input, proxy, {
      now: validMinimal.now,
      ...trust,
    });
  });
  assert.equal(r!.subjectMatches, null);
  assert.deepEqual(r!.subjectReasons, ["expected_subject_invalid"]);
});

// --- receipt subject unreadable ------------------------------------------

test("receipt with a non-string subject field: null + receipt_subject_unavailable", () => {
  const broken = { ...validMinimal.input, mintAddress: 42 };
  const r = verifyReceiptV1ForSubject(broken, goodSubject(), {
    now: validMinimal.now,
    ...trust,
  });
  assert.equal(r.valid, false); // shape failure in the kernel
  assert.equal(r.subjectMatches, null);
  assert.deepEqual(r.subjectReasons, ["receipt_subject_unavailable"]);
});

test("revoked-Proxy receipt is contained across every axis", () => {
  const { proxy, revoke } = Proxy.revocable({ ...validMinimal.input }, {});
  revoke();
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1ForSubject(proxy, goodSubject(), {
      now: validMinimal.now,
      ...trust,
    });
  });
  assert.equal(r!.valid, false);
  assert.equal(r!.keyTrusted, false, "a receipt with no readable signer is never trusted");
  assert.equal(r!.subjectMatches, null);
  assert.deepEqual(r!.subjectReasons, ["receipt_subject_unavailable"]);
});

test("live throwing-getter receipt is contained, never an exception", () => {
  // The kernel's shape walk cannot contain a LIVE hostile accessor (revoked
  // proxies are caught at the entry guard; live ones throw mid-walk). The
  // partner wrapper must still be total: a bounded, closed outcome.
  const hostile: Record<string, unknown> = {};
  for (const k of Object.keys(validMinimal.input)) {
    Object.defineProperty(hostile, k, {
      enumerable: true,
      get() {
        throw new Error("hostile getter: " + k);
      },
    });
  }
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1ForSubject(hostile, goodSubject(), {
      now: validMinimal.now,
      ...trust,
    });
  });
  assert.equal(r!.valid, false);
  assert.ok(r!.reasons.includes("receipt_uninspectable"));
  assert.equal(r!.keyTrusted, false, "unreadable signer resolves closed");
  assert.equal(r!.subjectMatches, null);
  assert.deepEqual(r!.subjectReasons, ["receipt_subject_unavailable"]);
});

// --- stable-capture (subject-binding TOCTOU) -------------------------------
//
// Integrity and binding must consume ONE captured receipt. A stateful get
// trap can show the signed tuple to the kernel's reads and a different tuple
// to a later binding read over the same live object; if the axes do not share
// a single capture, a receipt signed for subject A reports subjectMatches
// true for requested subject B. The wrapper therefore snapshots the receipt
// once (descriptor-safe, each declared field read exactly once, deeply
// frozen) and never re-reads the caller's live object.

const statefulReceiptProxy = (
  field: "chain" | "mintAddress" | "tokenProgramAddress",
  lateValue: string,
): unknown => {
  const genuine = { ...validMinimal.input } as Record<string, unknown>;
  let reads = 0;
  return new Proxy(genuine, {
    get(target, prop, receiver) {
      if (prop === field) {
        reads += 1;
        // The integrity kernel reads each subject field exactly twice (shape
        // walk, then signed-body extraction); only LATER reads — a separate
        // binding pass over the live object — would see the flipped value.
        if (reads > 2) return lateValue;
      }
      return Reflect.get(target, prop, receiver);
    },
  });
};

for (const [field, attacker] of [
  ["mintAddress", OTHER_MINT],
  ["tokenProgramAddress", OTHER_PROGRAM],
] as const) {
  test(`stateful ${field} get trap cannot show binding a different subject than integrity`, () => {
    // The caller requested the ATTACKER tuple; the signature belongs to the
    // genuine one. Correct: valid crypto, binding FALSE against the captured
    // genuine subject. Vulnerable (kernel verifies the live object, binding
    // re-reads it): the trap flips the late read to the requested value and
    // subjectMatches comes back true.
    const expected = { ...goodSubject(), [field]: attacker };
    const r = verifyReceiptV1ForSubject(statefulReceiptProxy(field, attacker), expected, {
      now: validMinimal.now,
      ...trust,
    });
    assert.equal(r.valid, true);
    assert.equal(r.keyTrusted, true);
    assert.equal(r.subjectMatches, false);
    assert.deepEqual(r.subjectReasons, [
      field === "mintAddress"
        ? "subject_mint_mismatch"
        : "subject_token_program_mismatch",
    ]);
  });
}

test("stateful chain get trap cannot break an intact binding", () => {
  // The frozen 0.1.0 contract admits only "solana-mainnet" as the expected
  // chain, so the chain trap runs the other way: the genuine namespace is
  // signed AND requested, and the late read flips to a foreign one. Both axes
  // must consume the captured value, so binding stays true.
  const r = verifyReceiptV1ForSubject(
    statefulReceiptProxy("chain", "solana-devnet"),
    goodSubject(),
    { now: validMinimal.now, ...trust },
  );
  assert.equal(r.valid, true);
  assert.equal(r.subjectMatches, true);
  assert.deepEqual(r.subjectReasons, []);
});

// --- required trust policy ------------------------------------------------

test("omitted trust policy: keyTrusted false + trust_config_invalid, never absent", () => {
  for (const opts of [undefined, {}]) {
    const r = verifyReceiptV1ForSubject(validMinimal.input, goodSubject(), {
      now: validMinimal.now,
      ...opts,
    });
    assert.equal(r.keyTrusted, false);
    assert.ok(r.reasons.includes("trust_config_invalid"), JSON.stringify(r.reasons));
    // Other axes are unaffected by the malformed policy.
    assert.equal(r.valid, true);
    assert.equal(r.subjectMatches, true);
  }
});

test("explicitly omitted options argument also fails closed and typed", () => {
  const r = verifyReceiptV1ForSubject(
    validMinimal.input,
    goodSubject(),
    undefined as never,
  );
  assert.equal(r.keyTrusted, false);
  assert.ok(r.reasons.includes("trust_config_invalid"));
});

const BAD_POLICIES: Array<[string, unknown]> = [
  ["malformed trustedKeys", { trustedKeys: 42 }],
  ["non-boolean allowUntrustedKey", { allowUntrustedKey: "true" }],
  ["allowUntrustedKey false without keys", { allowUntrustedKey: false }],
];
for (const [label, policy] of BAD_POLICIES) {
  test(`malformed policy (${label}): trust_config_invalid, no throw`, () => {
    let r;
    assert.doesNotThrow(() => {
      r = verifyReceiptV1ForSubject(validMinimal.input, goodSubject(), {
        now: validMinimal.now,
        ...(policy as Record<string, unknown>),
      });
    });
    assert.equal(r!.keyTrusted, false, label);
    assert.ok(r!.reasons.includes("trust_config_invalid"), label);
    assert.equal(r!.subjectMatches, true, label);
  });
}

test("typed opt-out allowUntrustedKey:true is honored, not an error", () => {
  const r = verifyReceiptV1ForSubject(validMinimal.input, goodSubject(), {
    now: validMinimal.now,
    allowUntrustedKey: true,
  });
  assert.equal(r.keyTrusted, false);
  assert.ok(r.reasons.includes("key_trust_not_evaluated"));
  assert.equal(r.subjectMatches, true);
});

test("hostile options object (throwing getters) is contained", () => {
  const hostile = {};
  for (const k of ["now", "trustedKeys", "allowUntrustedKey"]) {
    Object.defineProperty(hostile, k, {
      enumerable: true,
      get() {
        throw new Error("hostile option getter");
      },
    });
  }
  let r;
  assert.doesNotThrow(() => {
    r = verifyReceiptV1ForSubject(validMinimal.input, goodSubject(), hostile as never);
  });
  assert.equal(r!.keyTrusted, false);
  assert.ok(r!.reasons.includes("trust_config_invalid"));
  assert.equal(r!.subjectMatches, true);
});

// --- axis independence under tampering and wrong keys ---------------------

test("tampered receipt with intact subject: integrity fails, binding still true", () => {
  const r = verifyReceiptV1ForSubject(tamperedFinding.input, goodSubject(), {
    now: tamperedFinding.now,
    ...trust,
  });
  assert.equal(r.valid, false);
  assert.ok(r.reasons.includes("payload_hash_mismatch"));
  assert.equal(r.subjectMatches, true);
  assert.deepEqual(r.subjectReasons, []);
});

test("attacker Ed25519 receipt: cryptographically valid, untrusted under pin, binding intact", () => {
  const r = verifyReceiptV1ForSubject(wrongKey.input, goodSubject(), {
    now: wrongKey.now,
    ...trust,
  });
  assert.equal(r.valid, true, "self-consistent attacker signature is still valid crypto");
  assert.equal(r.keyTrusted, false);
  assert.ok(r.reasons.includes("key_untrusted"));
  assert.equal(r.subjectMatches, true);
});

test("wrong-key receipt verified against its own key: trusted, binding intact", () => {
  const r = verifyReceiptV1ForSubject(wrongKey.input, goodSubject(), {
    now: wrongKey.now,
    trustedKeys: [wrongKey.input.signerPublicKey as string],
  });
  assert.equal(r.valid, true);
  assert.equal(r.keyTrusted, true);
  assert.equal(r.subjectMatches, true);
});
