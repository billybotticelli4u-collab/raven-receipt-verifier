// Raven receipt-evm-v1 — open verification (raven-receipt-evm / v1).
//
// The §9.6 procedure with the EVM shape and domain: shape, byte-exact
// disclaimer, forbidden-word re-check, payload hash + receiptId over the
// canonical preimage, ed25519 over the domain-separated envelope; key trust
// and freshness reported independently. Hostile input is contained
// (canonicalization_failed), unparseable timestamps fail closed. Depends on
// nothing networked.

import { createHash, createPublicKey, verify as cryptoVerify } from "node:crypto";

import { canonicalJson } from "./canonicalJson.ts";
import {
  RECEIPT_EVM_DOMAIN,
  RECEIPT_EVM_VERSION,
  RECEIPT_EVM_ID_PREFIX,
  RECEIPT_EVM_DISCLAIMER,
  RECEIPT_EVM_BODY_FIELDS,
  RECEIPT_EVM_FIELDS,
  collectStrings,
  findForbiddenWords,
  type ReceiptEvmV1Body,
} from "./receiptEvmV1.ts";
import {
  resolveKeyTrust,
  sanitizeOptions,
  decodeCanonicalBase64,
  decodeCanonicalEd25519Spki,
  type VerifyReceiptOptions,
} from "./verifyReceiptV1.ts";
import { assertEd25519SignatureDomain } from "./ed25519KeyDomain.ts";
import { isInspectableObject } from "./receiptRules.ts";

/** EVM verifier result; intentionally does not acquire Solana rules fields. */
export interface VerifyReceiptEvmResult {
  valid: boolean;
  stale: boolean;
  reasons: string[];
  keyTrusted: boolean;
}

const publicKeyCache = new Map<string, ReturnType<typeof createPublicKey>>();
const PUBLIC_KEY_CACHE_MAX = 64;

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

const HEX_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const HEX_HASH = /^0x[0-9a-f]{64}$/;

const checkShape = (receipt: Record<string, unknown>): string[] => {
  const reasons: string[] = [];
  const expected = new Set<string>(RECEIPT_EVM_FIELDS);
  for (const k of Object.keys(receipt)) {
    if (!expected.has(k)) reasons.push(`shape_unexpected_field:${k}`);
  }
  for (const f of RECEIPT_EVM_FIELDS) {
    if (!(f in receipt)) reasons.push(`shape_missing_field:${f}`);
  }
  if (reasons.length > 0) return reasons;

  const r = receipt;
  const str = (k: string): void => {
    if (typeof r[k] !== "string") reasons.push(`shape_type:${k}`);
  };
  str("chain");
  if (typeof r.tokenAddress !== "string" || !HEX_ADDRESS.test(r.tokenAddress as string)) {
    reasons.push("shape_type:tokenAddress");
  }
  if (
    r.implementationAddress !== null &&
    (typeof r.implementationAddress !== "string" || !HEX_ADDRESS.test(r.implementationAddress as string))
  ) {
    reasons.push("shape_type:implementationAddress");
  }
  if (!Number.isInteger(r.blockNumber)) reasons.push("shape_type:blockNumber");
  if (typeof r.blockHash !== "string" || !HEX_HASH.test(r.blockHash as string)) {
    reasons.push("shape_type:blockHash");
  }
  str("timestamp");
  str("rulesVersion");
  str("findingTaxonomyVersion");
  if (!isStringArray(r.scopeChecksPerformed)) reasons.push("shape_type:scopeChecksPerformed");
  if (!isStringArray(r.scopeChecksNotPerformed)) reasons.push("shape_type:scopeChecksNotPerformed");
  if (!isStringArray(r.coverageGaps)) reasons.push("shape_type:coverageGaps");
  if (!isFindingArray(r.findings)) reasons.push("shape_type:findings");
  if (!isInterpretationArray(r.interpretations)) reasons.push("shape_type:interpretations");
  if (!Number.isInteger(r.maxAgeSeconds)) reasons.push("shape_type:maxAgeSeconds");
  str("disclaimer");
  str("payloadHash");
  str("receiptId");
  str("signature");
  str("signerPublicKey");
  return reasons;
};

const extractBody = (receipt: Record<string, unknown>): ReceiptEvmV1Body => {
  const body = {} as Record<string, unknown>;
  for (const f of RECEIPT_EVM_BODY_FIELDS) body[f] = receipt[f];
  return body as unknown as ReceiptEvmV1Body;
};

const toIso = (now: string | Date | undefined): string =>
  now === undefined ? new Date().toISOString() : typeof now === "string" ? now : now.toISOString();

const readSignerPublicKey = (receipt: unknown): string | null => {
  if (receipt === null || typeof receipt !== "object") return null;
  try {
    const value = (receipt as Record<string, unknown>).signerPublicKey;
    return typeof value === "string" ? value : null;
  } catch {
    return null;
  }
};

const resolveShapeFailureTrust = (
  receipt: unknown,
  opts: Pick<VerifyReceiptOptions, "trustedKeys" | "allowUntrustedKey">,
): { keyTrusted: boolean; reason?: string } => {
  const signerPublicKey = readSignerPublicKey(receipt);
  return resolveKeyTrust(signerPublicKey ?? "", opts);
};

/**
 * Verify a receipt-evm-v1. Same result contract as verifyReceiptV1:
 * `valid` gated only by shape/disclaimer/forbidden-words/hash/signature;
 * key trust and freshness reported independently, never fatal.
 */
export const verifyReceiptEvmV1 = (
  receipt: unknown,
  opts: VerifyReceiptOptions = {},
): VerifyReceiptEvmResult => {
  const safeOpts = sanitizeOptions(opts);
  const reasons: string[] = [];

  if (!isInspectableObject(receipt)) {
    const trust = resolveShapeFailureTrust(receipt, safeOpts);
    return {
      valid: false,
      stale: false,
      reasons:
        trust.reason === undefined
          ? ["shape_not_an_object"]
          : ["shape_not_an_object", trust.reason],
      keyTrusted: trust.keyTrusted,
    };
  }
  const r = receipt as Record<string, unknown>;

  const shapeReasons = checkShape(r);
  if (shapeReasons.length > 0) {
    const trust = resolveShapeFailureTrust(r, safeOpts);
    return {
      valid: false,
      stale: false,
      reasons: trust.reason === undefined ? shapeReasons : [...shapeReasons, trust.reason],
      keyTrusted: trust.keyTrusted,
    };
  }

  if (r.disclaimer !== RECEIPT_EVM_DISCLAIMER) reasons.push("disclaimer_mismatch");

  const body = extractBody(r);
  let recomputed: string | null = null;
  try {
    const forbidden = findForbiddenWords(collectStrings(body));
    for (const w of forbidden) reasons.push(`forbidden_word:${w}`);
    recomputed =
      "sha256:" + createHash("sha256").update(canonicalJson(body), "utf8").digest("hex");
  } catch {
    reasons.push("canonicalization_failed");
  }
  if (recomputed !== null && recomputed !== r.payloadHash) {
    reasons.push("payload_hash_mismatch");
  }
  if (r.receiptId !== RECEIPT_EVM_ID_PREFIX + (r.payloadHash as string)) {
    reasons.push("receipt_id_mismatch");
  }

  const signedBytes = canonicalJson({
    domain: RECEIPT_EVM_DOMAIN,
    version: RECEIPT_EVM_VERSION,
    payloadHash: r.payloadHash,
  });
  let signatureOk = false;
  try {
    const signerPublicKey = r.signerPublicKey as string;
    let pub = publicKeyCache.get(signerPublicKey);
    if (!pub) {
      const signerPublicKeyBytes = decodeCanonicalEd25519Spki(signerPublicKey);
      pub = createPublicKey({
        key: signerPublicKeyBytes,
        format: "der",
        type: "spki",
      });
      if (pub.asymmetricKeyType !== "ed25519") {
        throw new Error("not an Ed25519 SPKI key");
      }
      if (publicKeyCache.size >= PUBLIC_KEY_CACHE_MAX) {
        const oldest = publicKeyCache.keys().next().value;
        if (oldest !== undefined) publicKeyCache.delete(oldest);
      }
      publicKeyCache.set(signerPublicKey, pub);
    }
    const signatureBytes = decodeCanonicalBase64(r.signature as string);
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

  const valid = reasons.length === 0;

  const trust = resolveKeyTrust(r.signerPublicKey as string, safeOpts);
  const keyTrusted = trust.keyTrusted;
  if (trust.reason !== undefined) reasons.push(trust.reason);

  const ageSeconds =
    (Date.parse(toIso(safeOpts.now)) - Date.parse(r.timestamp as string)) / 1000;
  let stale: boolean;
  if (Number.isFinite(ageSeconds)) {
    stale = ageSeconds > (r.maxAgeSeconds as number);
    if (stale) reasons.push("stale");
  } else {
    stale = true;
    reasons.push("timestamp_unparseable");
  }

  return { valid, stale, reasons, keyTrusted };
};
