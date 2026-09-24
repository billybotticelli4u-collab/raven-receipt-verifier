/**
 * Node surface adapter for the Ed25519 key-domain predicate + crypto.verify.
 * Semantics: libsodium crypto_sign_verify_detached (key-domain) then OpenSSL verify.
 */
import { createPublicKey, verify as cryptoVerify } from "node:crypto";
import {
  assertEd25519SpkiDerKeyDomain,
  assertEd25519SignatureDomain,
  ED25519_KEY_DOMAIN_SEMANTICS,
} from "./ed25519KeyDomain.ts";
import { decodeCanonicalBase64, decodeCanonicalEd25519Spki } from "./verifyReceiptV1.ts";

export { ED25519_KEY_DOMAIN_SEMANTICS };

/** REFUSE/ACCEPT classification for the conformance corpus. */
export const verifyEd25519SpkiDetached = (
  keyB64: string,
  message: Uint8Array,
  sigB64: string,
): "ACCEPT" | "REFUSE" => {
  try {
    const der = decodeCanonicalEd25519Spki(keyB64); // includes key-domain assert
    assertEd25519SpkiDerKeyDomain(der);
    const sig = decodeCanonicalBase64(sigB64);
    assertEd25519SignatureDomain(sig);
    const pub = createPublicKey({ key: der, format: "der", type: "spki" });
    if (pub.asymmetricKeyType !== "ed25519") return "REFUSE";
    return cryptoVerify(null, Buffer.from(message), pub, sig) ? "ACCEPT" : "REFUSE";
  } catch {
    return "REFUSE";
  }
};
