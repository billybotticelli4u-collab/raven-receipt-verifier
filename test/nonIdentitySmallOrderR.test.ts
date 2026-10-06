import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assertEd25519SignatureRaw } from '../src/ed25519KeyDomain.ts';
import { verifyReceiptV1 } from '../src/index.ts';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/non-identity-small-order-r.json', import.meta.url), 'utf8'));
const genuine = JSON.parse(readFileSync(new URL('../fixtures/receipt-v1/production-receipt-v1-bonk-verified.json', import.meta.url), 'utf8'));
const vectors = Object.entries(fixture.vectors);
assert.deepEqual(vectors.map(([name]) => name), ['order2R_mixedKey', 'order8R_mixedKey']);

for (const [name, vector] of vectors) {
  test(name + ': explicit guard refuses non-identity R', () => {
    const sig = Buffer.from(vector.signature_b64, 'base64');
    assert.equal(sig.length, 64);
    assert.equal(sig.subarray(0, 32).toString('hex'), vector.R_hex);
    assert.notEqual(vector.R_hex, '01' + '00'.repeat(31));
    assert.throws(() => assertEd25519SignatureRaw(sig), /signature R has small order/);
  });
  test(name + ': trusted-key receipt is invalid with signature_invalid', () => {
    const result = verifyReceiptV1({ ...genuine.input, signerPublicKey: vector.key_b64, signature: vector.signature_b64 }, { now: genuine.now, trustedKeys: [vector.key_b64] });
    assert.equal(result.valid, false);
    assert.equal(result.keyTrusted, true);
    assert.ok(result.reasons.includes('signature_invalid'));
  });
}
test('non-identity corpus genuine receipt positive control', () => {
  const result = verifyReceiptV1(genuine.input, { now: genuine.now, trustedKeys: [genuine.input.signerPublicKey] });
  assert.equal(result.valid, true);
  assert.equal(result.keyTrusted, true);
});
