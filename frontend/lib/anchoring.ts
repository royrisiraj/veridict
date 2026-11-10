import type { Report } from "./types";
type Receipt = Report["chain_receipt"];
export function isPublicChain(receipt: Receipt): boolean {
  return receipt.mode === "evm" && /^evm:\d+$/.test(receipt.network) && receipt.network !== "evm:31337";
}
export function anchorLabel(receipt: Receipt): string {
  if (receipt.mode === "fixture") return receipt.network === "fixture-sealed-assets" ? "PACKAGED FIXTURE REFERENCE / NOT ON-CHAIN" : "SIMULATED LOCAL REFERENCE / NOT ON-CHAIN";
  if (!isPublicChain(receipt)) return "LOCAL DEVELOPMENT CHAIN";
  const id = receipt.network.slice(4);
  const names: Record<string, string> = { "1": "Ethereum", "11155111": "Sepolia", "84532": "Base Sepolia", "80002": "Polygon Amoy" };
  return `${names[id] ?? "Public EVM"} · chain ${id}`;
}
