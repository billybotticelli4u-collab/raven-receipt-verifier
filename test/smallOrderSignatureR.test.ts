import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { assertEd25519SignatureRaw } from '../src/ed25519KeyDomain.ts';
import { verifyEd25519SpkiDetached } from '../src/ed25519NodeVerify.ts';
import { verifyReceiptV1 } from '../src/index.ts';
const v=JSON.parse(readFileSync(new URL('./fixtures/small-order-r-keyholder.json',import.meta.url),'utf8'));
const msg=Buffer.from(v.message_b64,'base64'),sig=Buffer.from(v.signature_b64,'base64');
const genuine=JSON.parse(readFileSync(new URL('../fixtures/receipt-v1/production-receipt-v1-bonk-verified.json',import.meta.url),'utf8'));
test('key-holder small-order R is refused by the explicit Raven domain',()=>{
 // Native backends differ; the explicit domain refusal must be backend-independent.
 assert.equal(sig.subarray(0,32).toString('hex'),'01'+'00'.repeat(31));
 assert.throws(()=>assertEd25519SignatureRaw(sig),/signature R has small order/);
 assert.equal(verifyEd25519SpkiDetached(v.key_b64,msg,v.signature_b64),'REFUSE');
});
test('receipt refuses a trusted-key small-order R while retaining genuine positive control',()=>{
 const good=verifyReceiptV1(genuine.input,{now:genuine.now,trustedKeys:[genuine.input.signerPublicKey]});
 assert.equal(good.valid,true);
 const bad=verifyReceiptV1({...genuine.input,signerPublicKey:v.key_b64,signature:v.signature_b64},{now:genuine.now,trustedKeys:[v.key_b64]});
 assert.equal(bad.valid,false);
 assert.ok(bad.reasons.includes('signature_invalid'));
});
