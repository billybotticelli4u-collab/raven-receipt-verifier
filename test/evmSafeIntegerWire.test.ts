// Owner-ratified #149 numeric boundary. Read the committed wire bytes directly;
// do not reserialize through JS before the independent Python parse.
import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';
import { canonicalJson } from '../src/canonicalJson.ts';
import { RECEIPT_EVM_BODY_FIELDS } from '../src/receiptEvmV1.ts';
import { verifyReceiptEvmV1 } from '../src/verifyReceiptEvmV1.ts';

const raw = fs.readFileSync(new URL('../fixtures/evm-safe-integer-wire.json', import.meta.url), 'utf8');
const { vectors } = JSON.parse(raw);
for (const v of vectors) {
  test(`EVM safe integer wire: ${v.id}`, () => {
    assert.deepEqual(verifyReceiptEvmV1(v.input, {
      now: v.now, trustedKeys: [v.input.signerPublicKey],
    }), v.expected);
    if (v.canonicalBody !== undefined) {
      const body = Object.fromEntries(RECEIPT_EVM_BODY_FIELDS.map(k => [k, v.input[k]]));
      assert.equal(canonicalJson(body), v.canonicalBody);
    }
  });
}

test('raw decimal/exponent/rounded integer spellings reach this parser intact', () => {
  for (const field of ['blockNumber', 'maxAgeSeconds']) {
    for (const token of ['9007199254740993', '9007199254740993.0', '9.007199254740993e15', '123456.0', '1.23456e5']) {
      assert.ok(raw.includes(`"${field}":${token},`), `${field} ${token}`);
    }
  }
});

test('safe equivalent spellings retain the same body, payload hash, receipt ID and signature', () => {
  for (const field of ['blockNumber', 'maxAgeSeconds']) {
    const group = ['safe-integer', 'safe-decimal', 'safe-exponent'].map(s => vectors.find(v => v.id === `${field}-${s}`));
    for (const pick of [(v: any) => v.canonicalBody, (v: any) => v.input.payloadHash,
      (v: any) => v.input.receiptId, (v: any) => v.input.signature]) {
      assert.equal(new Set(group.map(pick)).size, 1);
    }
  }
});

test('direct-runtime non-finite values and unsafe negative integers reject before cryptographic evaluation', () => {
  for (const field of ['blockNumber', 'maxAgeSeconds']) {
    for (const value of [NaN, Infinity, -Infinity, -9007199254740992]) {
      const v = vectors[0];
      const input = { ...v.input, [field]: value, signature: 'intentionally invalid after structural gate' };
      const result = verifyReceiptEvmV1(input, { now: v.now, trustedKeys: [v.input.signerPublicKey] });
      assert.deepEqual(result, { valid: false, stale: false, reasons: [`shape_type:${field}`], keyTrusted: true });
    }
  }
});
