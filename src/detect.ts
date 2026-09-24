// Structural namespace detection for Raven receipts.
//
// Solana receipt-v1 carries mintAddress + slot; receipt-evm-v1 carries
// tokenAddress + blockNumber. Detection is a ROUTING convenience only — the
// selected verifier still enforces its full strict shape, so a mis-shaped
// artifact fails verification regardless of what detection guessed.

export type ReceiptNamespace = "solana" | "evm";

export const detectReceiptNamespace = (receipt: unknown): ReceiptNamespace | null => {
  if (receipt === null || typeof receipt !== "object" || Array.isArray(receipt)) return null;
  const r = receipt as Record<string, unknown>;
  if ("mintAddress" in r && "slot" in r) return "solana";
  if ("tokenAddress" in r && "blockNumber" in r) return "evm";
  return null;
};
