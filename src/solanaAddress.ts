// Canonical Solana public-key encoding check — dependency-free.
//
// A Solana public key is exactly 32 bytes, carried on the wire as base58.
// Base58 decoding is injective over the alphabet, so decode→re-encode is the
// identity for every in-alphabet string; the only canonicality questions are
// alphabet membership and decoded length. This validator answers both. It is
// used by the subject-binding wrapper to refuse malformed EXPECTED subjects —
// a partner typo must fail closed (`expected_subject_invalid`), never compare
// against a receipt as if it were a well-formed address.
//
// No network, no Solana SDK: alphabet + bignum arithmetic only.

const BASE58_ALPHABET =
  "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = new Map<string, bigint>(
  [...BASE58_ALPHABET].map((ch, i) => [ch, BigInt(i)]),
);

// 32 bytes encode to at most 44 base58 characters (58^44 > 2^256); anything
// longer cannot be a 32-byte value, so reject before doing any arithmetic.
const MAX_ENCODED_LENGTH = 44;

/**
 * True exactly when `value` is a string whose base58 decoding is precisely
 * 32 bytes — the canonical encoding of a Solana public key. Total over all
 * inputs: non-strings, empty strings, out-of-alphabet characters and wrong
 * decoded lengths all return false; no exception escapes.
 */
export const isCanonicalSolanaAddress = (value: unknown): boolean => {
  if (typeof value !== "string") return false;
  if (value.length === 0 || value.length > MAX_ENCODED_LENGTH) return false;
  let n = 0n;
  for (const ch of value) {
    const digit = BASE58_INDEX.get(ch);
    if (digit === undefined) return false;
    n = n * 58n + digit;
  }
  // Each leading '1' encodes one leading zero byte.
  let leadingZeros = 0;
  for (const ch of value) {
    if (ch !== "1") break;
    leadingZeros += 1;
  }
  let bodyLength = 0;
  while (n > 0n) {
    n >>= 8n;
    bodyLength += 1;
  }
  return leadingZeros + bodyLength === 32;
};
