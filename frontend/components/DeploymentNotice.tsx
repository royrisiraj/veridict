"use client";
import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Health } from "@/lib/types";

export default function DeploymentNotice() {
  const [health, setHealth] = useState<Health | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let active = true;
    api<Health>("health").then((value) => { if (active) setHealth(value); }).catch(() => { if (active) setFailed(true); });
    return () => { active = false; };
  }, []);
  const mode = health?.verification_mode;
  return <aside className="deployment-notice" data-testid="deployment-mode" role="status">
    <strong>{failed || mode === "UNAVAILABLE" ? "Verification service unavailable — no integrity assurance is available." : mode === "DEMO_FIXTURE" ? "Demo fixture mode — public blockchain anchoring is not enabled." : mode === "PUBLIC_CHAIN" ? "Public-chain backend configured — verify each passport independently." : health ? "Local development mode — public blockchain anchoring is not enabled." : "Checking deployment verification mode…"}</strong>
    {mode === "DEMO_FIXTURE" && <span>Evidence integrity and AI grounding are checked against packaged release references. Custom scanning is disabled.</span>}
  </aside>;
}
