// Real UI entry-point evidence; fixtures and outputs are not reviewer RESULT files.
// PLAYWRIGHT_MODULE (optional module URL/path), CHROMIUM_EXECUTABLE, OUT (external).
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync, writeFileSync, realpathSync } from 'node:fs';
import { createServer } from 'node:http';
import { dirname, resolve, relative, extname, basename } from 'node:path';
import { fileURLToPath } from 'node:url';

const repo = realpathSync(fileURLToPath(new URL('../../../../', import.meta.url)));
if (!process.env.OUT) throw new Error('OUT is required (outside the repository)');
const out = resolve(realpathSync(dirname(resolve(process.env.OUT))), basename(process.env.OUT));
assert(relative(repo, out).startsWith('../'), 'OUT must be outside the repository');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const readJSON = (path) => JSON.parse(readFileSync(path, 'utf8'));
const corpusPath = resolve(repo, 'packages/verify-js/test/ed25519-corpus/ed25519_corpus.json');
const corpus = readJSON(corpusPath);
const fixture = readJSON(resolve(repo, 'packages/verify-js/fixtures/receipt-v1/valid-minimal.json')).input;
const canonical = (x) => JSON.stringify(x, (_, v) => v && !Array.isArray(v) && typeof v === 'object' ? Object.fromEntries(Object.keys(v).sort().map(k => [k, v[k]])) : v);
// Public, deterministic test material only; no environment or signing-secret input.
const key = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 23)]), format: 'der', type: 'pkcs8' });
const message = (receipt) => Buffer.from(canonical({ domain: 'raven-receipt', version: 'v1', payloadHash: receipt.payloadHash }));
const resigned = { ...fixture, signerPublicKey: createPublicKey(key).export({ format: 'der', type: 'spki' }).toString('base64'), signature: sign(null, message(fixture), key).toString('base64') };
const cases = [
  { id: 'CONTROL_fixture_valid', receipt: fixture, valid: true, signatureInvalid: false },
  { id: 'CONTROL_synthetic_key_valid', receipt: resigned, valid: true, signatureInvalid: false },
  { id: 'CONTROL_signature_tamper', receipt: { ...resigned, signature: Buffer.alloc(64).toString('base64') }, valid: false, signatureInvalid: true },
  { id: 'CONTROL_payload_tamper', receipt: { ...resigned, slot: resigned.slot + 1 }, valid: false, signatureInvalid: false },
];
for (const vector of corpus.vectors) {
  const raw = Buffer.from(vector.msg, 'base64');
  const signed = JSON.parse(raw.toString('utf8'));
  assert.equal(canonical(signed), raw.toString('utf8'), `${vector.id}: actual message must be reproducible without changing bytes`);
  const receipt = { ...fixture, payloadHash: signed.payloadHash, receiptId: 'raven-receipt-v1:' + signed.payloadHash, signerPublicKey: vector.key, signature: vector.sig };
  assert.deepEqual(message(receipt), raw, `${vector.id}: wrong signed message`);
  cases.push({ id: vector.id, class: vector.class, corpusExpected: vector.expected, receipt, valid: false, signatureInvalid: vector.expected !== 'ACCEPT', messageBase64: vector.msg });
}
const fullCaseCount = cases.length;
if (process.env.CASE_LIMIT) cases.splice(Number(process.env.CASE_LIMIT));
let chromium;
try { ({ chromium } = await import(process.env.PLAYWRIGHT_MODULE || 'playwright')); }
catch (e) { console.log(JSON.stringify({ status: 'NOT_EXECUTED', pass: false, reason: 'Playwright unavailable: ' + e.message })); process.exit(2); }
const wrapper = `export * from './receipt-verify.js?real=1';
import {verifyReceiptV1 as real} from './receipt-verify.js?real=1';
export async function verifyReceiptV1(receipt, options) {
 const call = {input: JSON.stringify(receipt), stack: new Error().stack, result: null, error: null};
 try { call.result = await real(receipt, options); return call.result; }
 catch(e) { call.error = String(e); throw e; }
 finally { (window.__calls ||= []).push(call); }
}`;
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_EXECUTABLE || undefined, headless: true });
const report = { status: 'EXECUTED', node: process.version, browser: browser.version(), corpusSHA256: sha(readFileSync(corpusPath)), instrumentation: 'Pass-through verifier import wrapper and WebCrypto byte recorder; real verifier bytes served unchanged. Only backend receipt delivery is simulated; no live service contacted.', surfaces: [], rows: [] };
try {
  for (const [app, entry] of [['raven-blink', 'fragment'], ['raven-blink', 'api'], ['raven-receipt-page', 'submit']]) {
    const root = resolve(repo, 'apps', app, 'public');
    const server = createServer((req, res) => {
      try {
        const path = resolve(root, '.' + decodeURIComponent(new URL(req.url, 'http://local').pathname));
        assert(relative(root, realpathSync(path)).startsWith('..') === false);
        res.setHeader('Content-Type', ({ '.js': 'text/javascript', '.html': 'text/html', '.json': 'application/json', '.svg': 'image/svg+xml' })[extname(path)] || 'application/octet-stream');
        res.end(readFileSync(path));
      } catch { res.writeHead(404); res.end('not found'); }
    });
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const origin = `http://127.0.0.1:${server.address().port}`;
    const context = await browser.newContext({ serviceWorkers: 'block' });
    let current, deliveries = 0;
    const blocked = [];
    const cors = { 'access-control-allow-origin': origin, 'access-control-allow-headers': 'content-type', 'access-control-allow-methods': 'POST, OPTIONS' };
    await context.route('**/*', async route => {
      const request = route.request(); const url = new URL(request.url());
      if (url.origin === origin && url.pathname === '/receipt-verify.js' && !url.search) return route.fulfill({ status: 200, contentType: 'text/javascript', body: wrapper });
      if ((url.origin === origin && url.pathname === '/api/receipt') || url.href === 'https://raven-hosted-verifier.onrender.com/receipt/v1') {
        if (request.method() === 'OPTIONS') return route.fulfill({ status: 204, headers: cors });
        deliveries++;
        return route.fulfill({ status: 200, headers: cors, contentType: 'application/json', body: JSON.stringify(current) });
      }
      if (url.origin === origin) return route.continue();
      blocked.push(url.origin + url.pathname); return route.abort('blockedbyclient');
    });
    const page = await context.newPage();
    await page.addInitScript(() => {
      window.__calls = []; window.__cryptoMessages = [];
      // about:blank has no secure-context SubtleCrypto. The real localhost
      // document must still supply it and record the positive-control bytes.
      if (!globalThis.crypto?.subtle) return;
      const verify = crypto.subtle.verify.bind(crypto.subtle);
      crypto.subtle.verify = async (algorithm, key, signature, data) => {
        window.__cryptoMessages.push(btoa(String.fromCharCode(...new Uint8Array(data))));
        return verify(algorithm, key, signature, data);
      };
    });
    const errors = [], consoleErrors = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('console', msg => { if (msg.type() === 'error') consoleErrors.push(msg.text()); });
    try {
      let sequence = 0;
      for (const test of cases) {
        current = test.receipt; deliveries = 0; errors.length = 0; consoleErrors.length = 0; blocked.length = 0;
        const row = { app, entry, id: test.id, class: test.class || 'control', corpusExpected: test.corpusExpected ?? null, expected: { valid: test.valid, signatureInvalid: test.signatureInvalid }, inputSHA256: sha(JSON.stringify(current)), messageBase64: test.messageBase64 ?? message(current).toString('base64') };
        try {
          await page.goto('about:blank'); // Fragment changes alone do NOT rerun an ES module.
          const url = app === 'raven-blink'
            ? `${origin}/receipt.html?case=${++sequence}${entry === 'api' ? '&mint=' + encodeURIComponent(current.mintAddress) : '#receipt=' + Buffer.from(JSON.stringify(current)).toString('base64url')}`
            : `${origin}/index.html?case=${++sequence}`;
          await page.goto(url, { waitUntil: 'load' });
          if (entry === 'submit') {
            await page.waitForFunction(() => window.__calls.length === 1 && document.querySelector('#r-verdict')?.textContent.trim(), null, { timeout: 6000 });
            row.startupDemo = await page.evaluate(() => window.__calls[0]);
            assert.equal(row.startupDemo.result?.valid, true, 'startup demo failed its positive control');
            await page.evaluate(() => { window.__calls = []; window.__cryptoMessages = []; document.querySelector('#r-verdict').textContent = ''; });
            await page.fill('#mint', current.mintAddress); await page.click('#getBtn');
          }
          await page.waitForFunction(() => window.__calls.length > 0 && document.querySelector('#r-verdict')?.textContent.trim(), null, { timeout: 6000 });
          Object.assign(row, await page.evaluate(() => ({ calls: window.__calls, cryptoMessages: window.__cryptoMessages, dom: { title: document.title, verdict: document.querySelector('#r-verdict')?.textContent, reasons: document.querySelector('#r-reasons')?.textContent, demoHidden: document.querySelector('#demoBanner')?.classList.contains('hidden') ?? null, raw: document.querySelector('#r-raw')?.textContent ?? null } })));
          row.deliveries = deliveries;
          assert.equal(row.calls.length, 1, 'unexpected extra verifier calls / demo fallback');
          assert.equal(row.calls[0].input, JSON.stringify(current), 'different receipt or startup demo measured');
          assert.equal(row.calls[0].error, null);
          assert.match(row.calls[0].stack, app === 'raven-blink' ? /receipt-view\.js/ : /app\.js/);
          assert.equal(deliveries, entry === 'fragment' ? 0 : 1);
          if (entry === 'submit') assert.equal(row.dom.demoHidden, true, 'demo fallback is not the submitted receipt');
          const result = row.calls[0].result;
          assert.equal(result.valid, test.valid, 'full receipt validity');
          assert.equal(result.reasons.includes('signature_invalid'), test.signatureInvalid, 'signature axis');
          if (!test.signatureInvalid) assert.deepEqual(row.cryptoMessages, [row.messageBase64], 'actual corpus message did not reach WebCrypto');
          if (test.corpusExpected) assert(result.reasons.includes('payload_hash_mismatch'), 'corpus message is not a full signed body');
          assert.equal(errors.length, 0); assert.equal(consoleErrors.length, 0); assert.equal(blocked.length, 0);
          row.pass = true;
          if (test.id === 'CONTROL_fixture_valid' || test.id === 'CONTROL_signature_tamper') await page.screenshot({ path: resolve(dirname(out), `${app}-${entry}-${test.id}.png`), fullPage: true });
        } catch (e) { row.pass = false; row.failure = e.stack; console.error(`${app}/${entry}/${test.id}: ${e.message}`); }
        row.errors = [...errors]; row.consoleErrors = [...consoleErrors]; row.blockedRequests = [...blocked]; report.rows.push(row);
      }
      const rows = report.rows.filter(r => r.app === app && r.entry === entry);
      report.surfaces.push({ app, entry, verifierSHA256: sha(readFileSync(resolve(root, 'receipt-verify.js'))), entrySHA256: sha(readFileSync(resolve(root, app === 'raven-blink' ? 'receipt-view.js' : 'app.js'))), total: rows.length, pass: rows.filter(r => r.pass).length, fail: rows.filter(r => !r.pass).length });
      console.log(JSON.stringify(report.surfaces.at(-1)));
    } finally { await context.close(); await new Promise(r => server.close(r)); }
  }
} finally { await browser.close(); }
report.complete = cases.length === fullCaseCount;
report.pass = report.complete && report.rows.length === fullCaseCount * 3 && report.rows.every(r => r.pass);
writeFileSync(out, JSON.stringify(report, null, 2) + '\n', { flag: 'wx' });
console.log(JSON.stringify({ pass: report.pass, rows: report.rows.length, browser: report.browser, output: out }));
if (!report.pass) process.exitCode = 1;
