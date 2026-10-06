// Fixture parity guard (issue #13, item 1).
//
// This package vendors the app's golden vectors. The drift defense — "both copies
// run the same fixtures" — only holds while the copies are byte-identical, so this
// test enforces it: every fixture here must be byte-identical to its counterpart in
// apps/launchguard-acp/fixtures/receipt-v1/, and vice versa (no file may exist on
// one side only).
//
// Runs only inside the monorepo; skips (loudly) when the app directory is absent,
// e.g. if this package is ever consumed standalone.

import assert from "node:assert/strict";
import fs from "node:fs";
import test from "node:test";
import { fileURLToPath } from "node:url";

const PKG_DIR = fileURLToPath(new URL("../fixtures/receipt-v1/", import.meta.url));
const APP_DIR = fileURLToPath(
  new URL("../../../apps/launchguard-acp/fixtures/receipt-v1/", import.meta.url),
);

test("vendored fixtures are byte-identical to the app's golden vectors", (t) => {
  if (!fs.existsSync(APP_DIR)) {
    t.skip("app fixtures not present (standalone checkout) — parity enforced in monorepo CI");
    return;
  }
  const pkgFiles = fs.readdirSync(PKG_DIR).filter((f) => f.endsWith(".json")).sort();
  const appFiles = fs.readdirSync(APP_DIR).filter((f) => f.endsWith(".json")).sort();
  assert.deepEqual(
    pkgFiles,
    appFiles,
    "fixture file sets diverged between packages/verify-js and apps/launchguard-acp",
  );
  for (const f of pkgFiles) {
    const pkgBytes = fs.readFileSync(PKG_DIR + f);
    const appBytes = fs.readFileSync(APP_DIR + f);
    assert.ok(
      pkgBytes.equals(appBytes),
      `fixture ${f} differs byte-for-byte between the package and the app — re-vendor deliberately, in one commit, on both sides`,
    );
  }
});
