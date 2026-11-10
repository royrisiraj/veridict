import { ShieldCheck, ShieldAlert, CircleHelp } from "lucide-react";
import type { Report, Verification } from "@/lib/types";
import { isPublicChain } from "@/lib/anchoring";

export default function VerificationBadge({ verification, receipt }: { verification: Verification; receipt: Report["chain_receipt"] }) {
  const Icon = verification.status === "SUPPORTED" ? ShieldCheck : verification.status === "TAMPERED" ? ShieldAlert : CircleHelp;
  return <div className={`verification ${verification.status.toLowerCase()}`} role="status" data-testid="verification-status">
    <Icon size={22}/><div><strong>{verification.status}</strong><p>{verification.status === "SUPPORTED" ? "Evidence matches the reference seal. All claims are grounded." : verification.status === "TAMPERED" ? "The candidate evidence does not match the reference seal." : "One or more AI claims lack valid supporting evidence."}</p><p>PUBLIC-CHAIN ANCHOR: {isPublicChain(receipt) ? verification.root_match ? "ROOT MATCH CONFIRMED" : "ROOT MISMATCH" : "NOT ENABLED"}</p></div>
    <div className="verification-flags"><span>INTEGRITY {verification.root_match ? "✓" : "✕"}</span><span>GROUNDING {verification.claim_grounding ? "✓" : "✕"}</span></div>
  </div>;
}
