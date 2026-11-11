"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowLeft, ArrowUpRight, Check, ChevronDown, ExternalLink, Fingerprint, GitBranch, LockKeyhole, ShieldCheck } from "lucide-react";
import { api } from "@/lib/api";
import { riskLabels, type AnchorStatus, type Bundle, type Report, type TamperResult, type Verification } from "@/lib/types";
import VerificationBadge from "./VerificationBadge";
import TamperPanel from "./TamperPanel";
import { anchorLabel } from "@/lib/anchoring";

function canonical(value: unknown): string {
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  if (value !== null && typeof value === "object") return "{" + Object.entries(value).sort(([a], [b]) => a < b ? -1 : a > b ? 1 : 0).map(([key, item]) => JSON.stringify(key) + ":" + canonical(item)).join(",") + "}";
  return JSON.stringify(value);
}

export default function EvidencePassport({ report }: { report: Report }) {
  const [original, setOriginal] = useState(report);
  const [mutation, setMutation] = useState<TamperResult | null>(null);
  const [verification, setVerification] = useState<Verification | null>(null);
  const [error, setError] = useState("");
  const [highlight, setHighlight] = useState("");
  const [checking, setChecking] = useState(false);
  const [anchor, setAnchor] = useState<AnchorStatus | null>(null);
  const reportId = original.bundle.report_id;
  const bundle: Bundle = mutation?.mutated_bundle ?? original.bundle;
  const merkle = mutation?.mutated_merkle ?? original.merkle;
  const limitations = bundle.limitations ?? [];
  useEffect(() => {
    let active = true;
    api<Verification>(`reports/${reportId}/verify`, { method: "POST", body: "{}" }).then((value) => { if (active) setVerification(value); }).catch((e) => { if (active) setError(e.message); });
    api<AnchorStatus>(`reports/${reportId}/anchor`).then((value) => { if (active) setAnchor(value); }).catch(() => { if (active) setAnchor(null); });
    return () => { active = false; };
  }, [reportId]);
  async function verify() {
    setChecking(true); setError(""); setVerification(null);
    try { setVerification(await api<Verification>(`reports/${reportId}/verify`, { method: "POST", body: JSON.stringify({ candidate_bundle: bundle }) })); }
    catch (e) { setError((e as Error).message); }
    finally { setChecking(false); }
  }
  async function reset() {
    const clean = await api<Report>(`reports/${reportId}`);
    const checked = await api<Verification>(`reports/${reportId}/verify`, { method: "POST", body: "{}" });
    setOriginal(clean); setMutation(null); setVerification(checked); setError(""); setHighlight("");
  }
  function cite(id: string) {
    setHighlight(id);
    const target = document.getElementById(`leaf-${id}`);
    target?.scrollIntoView({ behavior: "smooth", block: "center" });
    target?.focus({ preventScroll: true });
  }
  return <div className="passport-page">
    <Link href="/" className="back-link"><ArrowLeft size={15}/>Back to investigation desk</Link>
    <div className="passport-heading"><div><span className="eyebrow"><Fingerprint size={14}/> SEALED//EVIDENCE</span><h1>Evidence Passport<span className="lime">.</span></h1><p className="passport-url">{bundle.normalized_url}</p></div><div className={`risk-banner risk-${bundle.risk.toLowerCase()}`}><span className="eyebrow">DETERMINISTIC VERDICT</span><strong>{riskLabels[bundle.risk]}</strong></div></div>
    <div className="passport-meta"><span>REPORT <code>{reportId.slice(0, 18)}…</code></span><span>{new Date(bundle.created_at).toLocaleString("en-IN", { timeZone: "Asia/Kolkata" })} IST</span><span>{bundle.provenance.collection.toUpperCase()} EVIDENCE</span><span>AI / {bundle.provenance.analyzer.toUpperCase()}</span></div>
    <div className="verification-row">{verification ? <VerificationBadge verification={verification} receipt={original.chain_receipt}/> : <div className="verification pending"><LockKeyhole size={22}/><div><strong>{error ? "VERIFICATION UNAVAILABLE" : "CHECKING INDEPENDENT REFERENCE"}</strong><p>{error || "Fetching the reference root and recomputing the evidence seal."}</p></div></div>}<button className="button secondary" disabled={checking} onClick={verify}><ShieldCheck size={16}/>{checking ? "Verifying…" : "Verify independently"}</button></div>
    {error && <p className="error-text" role="alert">{error}</p>}
    <div className="passport-grid"><div className="passport-main">
      <section className="panel anchor-panel"><div className="panel-heading"><h2><GitBranch size={18}/>The evidence commitment</h2><span className="status-chip">{anchorLabel(original.chain_receipt)}</span></div>
        <div className="merkle-diagram"><div className="merkle-root"><Fingerprint size={22}/><span>MERKLE ROOT<code>{merkle.root.slice(0, 22)}…{merkle.root.slice(-8)}</code></span></div><div className="tree-stem"/><div className="tree-leaves">{merkle.leaves.slice(0, 6).map((leaf) => <button key={leaf.id} onClick={() => cite(leaf.id)} className={verification?.leaf_validity[leaf.id] === false ? "invalid" : ""}>{leaf.id}<span>{leaf.hash.slice(0, 10)}…</span></button>)}</div><span className="micro">{merkle.leaves.length} TYPED LEAVES · SORTED PAIRS · ODD-LEAF PROMOTION</span></div>
        <div className="anchor-details"><div><label>ORIGINAL SEALED ROOT</label><code>{original.merkle.root}</code></div><div><label>NETWORK / SOURCE</label><span>{anchorLabel(anchor?.receipt ?? original.chain_receipt)}</span></div><div><label>TRANSACTION</label><code>{(anchor?.receipt ?? original.chain_receipt).tx_hash ?? "None — no confirmed registration transaction is available"}</code></div>{anchor?.contract_address && <div><label>SEPOLIA / CHAIN {anchor.chain_id} / {anchor.status.replaceAll("_", " ")}</label><code>{anchor.contract_address}</code>{anchor.receipt && <span>Block {anchor.receipt.block_number}</span>}{anchor.explorer_url && <a href={anchor.explorer_url} target="_blank" rel="noreferrer">View real transaction on Sepolia Etherscan <ExternalLink size={12}/></a>}</div>}</div>
      </section>
      <section className="coverage-section"><div className="section-mini-heading"><h2>Collection coverage</h2><span className="micro">UNKNOWN IS NEVER SAFE</span></div><div className="coverage-grid">{Object.entries(bundle.coverage).map(([key, value]) => <div key={key} className={value === "COMPLETE" ? "complete" : "incomplete"}><span>{key.replaceAll("_", " ")}</span><strong>{value === "COMPLETE" && <Check size={13}/>} {value}</strong></div>)}</div></section>
      <section className="claims-section"><div className="section-mini-heading"><h2>Grounded analysis</h2><span className="micro">AI EXPLAINS · CODE CLASSIFIES</span></div><div className="claims-list">{bundle.ai_claims.map((claim, index) => <article key={claim.id} className="claim-card"><span className="claim-number">{String(index + 1).padStart(2, "0")}</span><div><p>{claim.text}</p><div className="evidence-pills">{claim.evidence_ids.map((id) => <button key={id} className={bundle.evidence.some((e) => e.id === id) ? "" : "missing"} onClick={() => cite(id)}>{id}<ArrowUpRight size={11}/></button>)}</div></div></article>)}</div>{limitations.length > 0 && <div className="limitations"><strong>Collection limitations</strong><p>{limitations.join(" · ")}</p></div>}</section>
      <section className="leaves-section"><div className="section-mini-heading"><h2>Evidence ledger</h2><span className="micro">{merkle.leaves.length} SEALED COMPONENTS</span></div>{merkle.leaves.map((leaf) => <article tabIndex={-1} id={`leaf-${leaf.id}`} key={leaf.id} className={`leaf-card ${highlight === leaf.id ? "highlighted" : ""}`}>
        <div className="leaf-heading"><span className="leaf-type">{leaf.id}</span><span className="micro">{leaf.type.replaceAll("_", " ").toUpperCase()}</span><span className={`leaf-proof ${verification?.leaf_validity[leaf.id] === false ? "invalid" : ""}`}>{verification ? verification.leaf_validity[leaf.id] ? "SUPPORTED" : "ALTERED / UNSUPPORTED" : "UNCHECKED"}</span></div>
        <label>LEAF HASH</label><code className="leaf-hash">{leaf.hash}</code><details><summary>Canonical JSON & inclusion proof <ChevronDown size={14}/></summary><pre data-testid={`payload-${leaf.id}`}>{canonical(leaf.payload)}</pre><label>ORIGINAL PROOF AGAINST REGISTERED ROOT</label><pre>{JSON.stringify(original.merkle.proofs_by_id[leaf.id] ?? [], null, 2)}</pre></details>
      </article>)}</section>
      {bundle.evidence.some((e) => e.type === "threat_intel" && e.status === "COMPLETE" && e.data.provider === "google_safe_browsing" && e.data.matched) && <p className="muted">This destination may be unsafe. Google Safe Browsing can produce false positives and false negatives. <a href="https://safebrowsing.google.com/" target="_blank" rel="noreferrer">Advisory provided by Google <ExternalLink size={12}/></a></p>}
    </div><aside className="passport-sidebar"><TamperPanel reportId={reportId} result={mutation} onMutation={(result) => { setMutation(result); setVerification(result.verification); setError(""); setHighlight(result.tampered_leaf_id); }} onReset={reset}/><div className="integrity-note"><LockKeyhole size={20}/><h3>Integrity is a precise promise.</h3><p>A valid seal proves this evidence matches its registered commitment. It does not prove that the evidence is true, exhaustive, or current.</p></div></aside></div>
  </div>;
}
