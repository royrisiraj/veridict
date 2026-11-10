"use client";
import { useState } from "react";
import { FlaskConical, Fingerprint, GitBranch, ListMinus, RotateCcw, Sparkles } from "lucide-react";
import { api } from "@/lib/api";
import type { Mutation, TamperResult } from "@/lib/types";

const actions: { key: Mutation; label: string; caption: string; icon: typeof Fingerprint }[] = [
  { key: "tls_cert", label: "Mutate TLS fingerprint", caption: "Change one certificate byte", icon: Fingerprint },
  { key: "drop_threat_intel", label: "Delete threat intelligence", caption: "Remove a claim’s backing evidence", icon: ListMinus },
  { key: "alter_redirect", label: "Alter a redirect hop", caption: "Replace the recorded destination", icon: GitBranch },
  { key: "unground_ai_claim", label: "Inject an ungrounded claim", caption: "Cite evidence that does not exist", icon: Sparkles },
];

export default function TamperPanel({ reportId, result, onMutation, onReset }: {
  reportId: string; result: TamperResult | null; onMutation: (result: TamperResult) => void; onReset: () => Promise<void>;
}) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  async function mutate(mutation: Mutation) {
    setBusy(true); setError("");
    try { onMutation(await api<TamperResult>(`reports/${reportId}/tamper-demo`, { method: "POST", body: JSON.stringify({ mutation }) })); }
    catch (e) { setError((e as Error).message); }
    finally { setBusy(false); }
  }
  return <section className="tamper-panel" aria-labelledby="tamper-title">
    <div className="tamper-heading"><span className="square-icon"><FlaskConical size={20}/></span><span className="eyebrow">JUDGE’S TAMPER STUDIO</span><span className="status-chip">STATELESS</span></div>
    <h2 id="tamper-title">Break the evidence.<br/>Watch verification respond.</h2><p className="muted">Each mutation starts from the genuine sealed report. The original stays intact.</p>
    <div className="tamper-buttons">{actions.map(({ key, label, caption, icon: Icon }) => <button key={key} disabled={busy} onClick={() => mutate(key)} data-testid={`tamper-${key}`}><Icon size={19}/><span><strong>{label}</strong><small>{caption}</small></span><span className="mutation-arrow">↗</span></button>)}</div>
    {error && <p role="alert" className="error-text">{error}</p>}
    {result && <div className="hash-diff" data-testid="hash-diff"><span className="eyebrow">MUTATED LEAF / {result.tampered_leaf_id}</span><label>REGISTERED ROOT</label><code>{result.expected_root}</code><label>CANDIDATE ROOT</label><code className="changed-hash">{result.computed_root}</code><p>{result.verification.failures.map((f) => f.code.replaceAll("_", " ")).join(" · ")}</p></div>}
    <button className="button secondary full" disabled={busy} onClick={async () => { setBusy(true); setError(""); try { await onReset(); } catch (e) { setError((e as Error).message); } finally { setBusy(false); } }}><RotateCcw size={15}/>Reset to genuine sealed bundle</button>
  </section>;
}
