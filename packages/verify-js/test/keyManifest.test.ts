// Key-manifest chain tests: genesis self-signing, rotation handover (the OLD
// key signs the manifest that introduces the NEW key), pin enforcement, scoped
// key extraction, and every broken-link class. Ephemeral keys; nothing persisted.

import assert from "node:assert/strict";
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto";
import test from "node:test";

import {
  computeManifestHash,
  extractTrustedKeys,
  signKeyManifest,
  verifyManifestChain,
  type KeyManifestBody,
  type ManifestKey,
  type ManifestSigner,
  type SignedKeyManifest,
} from "../src/proposed.ts";

const makeKey = (): { signer: ManifestSigner; publicKeyBase64: string } => {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const publicKeyBase64 = publicKey.export({ format: "der", type: "spki" }).toString("base64");
  return {
    publicKeyBase64,
    signer: {
      publicKeyBase64,
      signBytes: (m) => cryptoSign(null, Buffer.from(m, "utf8"), privateKey).toString("base64"),
    },
  };
};

const keyEntry = (publicKeyBase64: string, keyId: string, over: Partial<ManifestKey> = {}): ManifestKey => ({
  keyId,
  publicKeyBase64,
  alg: "ed25519",
  scopes: ["receipt-v1", "attestation-v2"],
  status: "active",
  ...over,
});

const genesisWith = (k: ReturnType<typeof makeKey>): SignedKeyManifest =>
  signKeyManifest(
    {
      manifestVersion: 1,
      issuedAt: "2026-07-01T00:00:00.000Z",
      keys: [keyEntry(k.publicKeyBase64, "rvk_g")],
      previousManifestHash: null,
    },
    k.signer,
  );

test("genesis: self-signed by a key it lists active; verifies alone; pin enforced", () => {
  const g = makeKey();
  const genesis = genesisWith(g);
  const ok = verifyManifestChain([genesis]);
  assert.deepEqual(ok.reasons, []);
  assert.equal(ok.valid, true);
  assert.equal(ok.currentKeys.length, 1);

  const pinnedOk = verifyManifestChain([genesis], { pinnedGenesisHash: genesis.manifestHash });
  assert.equal(pinnedOk.valid, true);
  const pinnedBad = verifyManifestChain([genesis], { pinnedGenesisHash: "sha256:" + "0".repeat(64) });
  assert.equal(pinnedBad.valid, false);
  assert.ok(pinnedBad.reasons.includes("link_0:pinned_genesis_hash_mismatch"));
});

test("rotation: the OLD key signs the manifest introducing the NEW key; chain verifies; keys hand over", () => {
  const oldKey = makeKey();
  const newKey = makeKey();
  const genesis = genesisWith(oldKey);
  const rotation: KeyManifestBody = {
    manifestVersion: 2,
    issuedAt: "2026-07-02T00:00:00.000Z",
    keys: [
      keyEntry(oldKey.publicKeyBase64, "rvk_g", { status: "retiring", notAfter: "2026-08-01T00:00:00.000Z" }),
      keyEntry(newKey.publicKeyBase64, "rvk_n"),
    ],
    previousManifestHash: genesis.manifestHash,
  };
  const link2 = signKeyManifest(rotation, oldKey.signer); // continuity: old signs new

  const result = verifyManifestChain([genesis, link2], { pinnedGenesisHash: genesis.manifestHash });
  assert.deepEqual(result.reasons, []);
  assert.equal(result.valid, true);

  // Trusted set DURING the grace window contains both; after notAfter, old drops.
  const during = extractTrustedKeys(result.currentKeys, { scope: "receipt-v1", at: "2026-07-10T00:00:00.000Z" });
  assert.equal(during.size, 2);
  const after = extractTrustedKeys(result.currentKeys, { scope: "receipt-v1", at: "2026-09-01T00:00:00.000Z" });
  assert.deepEqual([...after], [newKey.publicKeyBase64]);
});

test("compromise rotation: revoked keys never qualify, at any time", () => {
  const g = makeKey();
  const n = makeKey();
  const genesis = genesisWith(g);
  const link2 = signKeyManifest(
    {
      manifestVersion: 2,
      issuedAt: "2026-07-02T00:00:00.000Z",
      keys: [keyEntry(g.publicKeyBase64, "rvk_g", { status: "revoked" }), keyEntry(n.publicKeyBase64, "rvk_n")],
      previousManifestHash: genesis.manifestHash,
    },
    g.signer,
  );
  const result = verifyManifestChain([genesis, link2]);
  assert.equal(result.valid, true);
  const trusted = extractTrustedKeys(result.currentKeys, { at: "2026-07-03T00:00:00.000Z" });
  assert.ok(!trusted.has(g.publicKeyBase64), "revoked key must never be trusted");
  assert.ok(trusted.has(n.publicKeyBase64));
});

test("broken links: unauthorized signer, hash break, version skip — all rejected", () => {
  const g = makeKey();
  const stranger = makeKey();
  const genesis = genesisWith(g);

  // A stranger (never listed) signs link 2: rejected.
  const hijack = signKeyManifest(
    {
      manifestVersion: 2,
      issuedAt: "2026-07-02T00:00:00.000Z",
      keys: [keyEntry(stranger.publicKeyBase64, "rvk_x")],
      previousManifestHash: genesis.manifestHash,
    },
    stranger.signer,
  );
  const hijacked = verifyManifestChain([genesis, hijack]);
  assert.equal(hijacked.valid, false);
  assert.ok(hijacked.reasons.includes("link_1:signer_not_authorized_by_previous"));
  assert.deepEqual(hijacked.currentKeys, []); // no keys from an invalid chain

  // Hash-chain break.
  const brokenHash = signKeyManifest(
    {
      manifestVersion: 2,
      issuedAt: "2026-07-02T00:00:00.000Z",
      keys: [keyEntry(g.publicKeyBase64, "rvk_g")],
      previousManifestHash: "sha256:" + "a".repeat(64),
    },
    g.signer,
  );
  assert.ok(
    verifyManifestChain([genesis, brokenHash]).reasons.includes("link_1:previous_hash_mismatch"),
  );

  // Version skip.
  const skipped = signKeyManifest(
    {
      manifestVersion: 3,
      issuedAt: "2026-07-02T00:00:00.000Z",
      keys: [keyEntry(g.publicKeyBase64, "rvk_g")],
      previousManifestHash: genesis.manifestHash,
    },
    g.signer,
  );
  assert.ok(
    verifyManifestChain([genesis, skipped]).reasons.includes("link_1:version_not_incrementing"),
  );
});

test("tampered manifest body breaks its hash and the chain", () => {
  const g = makeKey();
  const genesis = genesisWith(g);
  const tampered = { ...genesis, issuedAt: "2026-01-01T00:00:00.000Z" };
  const result = verifyManifestChain([tampered]);
  assert.equal(result.valid, false);
  assert.ok(result.reasons.includes("link_0:manifest_hash_mismatch"));
  assert.notEqual(computeManifestHash(tampered), genesis.manifestHash);
});

test("scope filtering: a transparency-log key is not a receipt key", () => {
  const g = makeKey();
  const logKey = makeKey();
  const genesis = signKeyManifest(
    {
      manifestVersion: 1,
      issuedAt: "2026-07-01T00:00:00.000Z",
      keys: [
        keyEntry(g.publicKeyBase64, "rvk_g"),
        keyEntry(logKey.publicKeyBase64, "rvk_log", { scopes: ["transparency-log"] }),
      ],
      previousManifestHash: null,
    },
    g.signer,
  );
  const result = verifyManifestChain([genesis]);
  assert.equal(result.valid, true);
  const receiptKeys = extractTrustedKeys(result.currentKeys, { scope: "receipt-v1" });
  assert.ok(!receiptKeys.has(logKey.publicKeyBase64));
  const logKeys = extractTrustedKeys(result.currentKeys, { scope: "transparency-log" });
  assert.deepEqual([...logKeys], [logKey.publicKeyBase64]);
});
