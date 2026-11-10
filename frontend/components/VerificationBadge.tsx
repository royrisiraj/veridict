import { ShieldCheck, ShieldAlert, CircleHelp } from "lucide-react";
import type { Verification } from "@/lib/types";

export default function VerificationBadge({ verification }: { verification: Verification }) {
  const Icon = verification.status === "SUPPORTED" ? ShieldCheck : verification.status === "TAMPERED" ? ShieldAlert : CircleHelp;
  return <div className={`verification ${verification.status.toLowerCase()}`} role="status" data-testid="verification-status">
    <Icon size={22}/><div><strong>{verification.status}</strong><p>{verification.status === "SUPPORTED" ? "Evidence matches the registered seal. All claims are grounded." : verification.status === "TAMPERED" ? "The candidate evidence does not match the registered seal." : "One or more AI claims lack valid supporting evidence."}</p></div>
    <div className="verification-flags"><span>INTEGRITY {verification.root_match ? "✓" : "✕"}</span><span>GROUNDING {verification.claim_grounding ? "✓" : "✕"}</span></div>
  </div>;
}
