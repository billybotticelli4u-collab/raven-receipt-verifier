import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

// These are monorepo evidence gates, not a claim that applications execute the
// shared predicate or that a copied verifier has a production caller.
const repo = fileURLToPath(new URL('../../../', import.meta.url));
const acpKeyDomain = resolve(repo, 'apps/launchguard-acp/src/receipt/ed25519KeyDomain.ts');
const packageKeyDomain = resolve(repo, 'packages/verify-js/src/ed25519KeyDomain.ts');
const blinkVerifier = resolve(repo, 'apps/raven-blink/public/receipt-verify.js');
const receiptPageVerifier = resolve(repo, 'apps/raven-receipt-page/public/receipt-verify.js');

test('ACP and package Ed25519 key-domain sources are byte-identical', (t) => {
  if (!existsSync(acpKeyDomain) || !existsSync(packageKeyDomain)) {
    t.skip('monorepo Ed25519 sources absent (standalone public checkout)');
    return;
  }
  assert.deepEqual(readFileSync(acpKeyDomain), readFileSync(packageKeyDomain));
});
test('the two browser verifier sources are byte-identical', (t) => {
  if (!existsSync(blinkVerifier) || !existsSync(receiptPageVerifier)) {
    t.skip('monorepo browser verifier sources absent (standalone public checkout)');
    return;
  }
  assert.deepEqual(readFileSync(blinkVerifier), readFileSync(receiptPageVerifier));
});
for (const surface of ['verify-js', 'for-subject', 'standalone-raven-receipt-verifier', 'acp', 'browser-blink', 'browser-receipt-page']) {
  test(`${surface} cannot silently execute the shared predicate`, () => {
    const dir = mkdtempSync(resolve(tmpdir(), 'raven-surface-'));
    try {
      const r = spawnSync(process.execPath, [fileURLToPath(new URL('./ed25519-corpus/run_surface.mjs', import.meta.url))], { env: { PATH: process.env.PATH, SURFACE: surface, TRIALS: '1', OUT: resolve(dir, 'result.json') }, encoding: 'utf8' });
      assert.notEqual(r.status, 0);
      const report = JSON.parse(r.stdout);
      assert.equal(report.status, 'NOT_EXECUTED');
      assert.equal(report.requested_surface, surface);
      assert.equal(report.executed_implementation, null);
      assert.equal(report.pass, false);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });
}
