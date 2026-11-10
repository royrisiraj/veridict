"use client";
import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ArrowUpRight, Check, LoaderCircle, LockKeyhole, ShieldAlert, X } from "lucide-react";
import { streamInvestigation } from "@/lib/api";
import { riskLabels, type InvestigationInput, type Report } from "@/lib/types";

const stages = [
  ["url", "URL & IDNA normalization"], ["redirects", "SSRF & redirect inspection"],
  ["tls", "TLS X.509 certificate"], ["threat_intel", "Threat intelligence"],
  ["ai", "AI claim grounding"], ["seal", "Merkle seal & registration"],
];

export default function InterceptGate({ input, onClose }: { input: InvestigationInput; onClose: () => void }) {
  const [stage, setStage] = useState("url");
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current!;
    const before = document.activeElement as HTMLElement | null;
    dialog.showModal();
    return () => { dialog.close(); before?.focus(); };
  }, []);
  useEffect(() => {
    const controller = new AbortController();
    streamInvestigation(input, controller.signal, setStage).then(setReport).catch((failure) => {
      if (!controller.signal.aborted) setError(failure.message);
    });
    return () => controller.abort();
  }, [input, attempt]);
  const index = stages.findIndex(([key]) => key === stage);
  const ssrf = report?.bundle.evidence.some((e) => e.type === "redirect" && e.data.ssrf_blocked);
  const canProceed = Boolean(report && !input.fixture_id && !ssrf && /^https?:\/\//.test(input.url));
  return <dialog ref={ref} className="gate" aria-labelledby="gate-title" onCancel={onClose}>
    <div className="gate-heading"><span className="eyebrow"><LockKeyhole size={14}/> TRUST//INTERCEPT</span><button className="icon-button" onClick={onClose} aria-label="Close gate"><X size={20}/></button></div>
    <h2 id="gate-title">Navigation intercepted.</h2><p className="muted">Inspect the destination before extending trust.</p>
    <div className="blocked-destination"><LockKeyhole size={16}/><span>{input.url}</span></div>
    <div className="progress-track"><div style={{ width: `${report ? 100 : Math.max(5, index / stages.length * 100)}%` }}/></div>
    <ol className="stage-list">{stages.map(([key, label], i) => <li key={key} className={report || i < index ? "done" : i === index ? "active" : ""}>
      {report || i < index ? <Check size={16}/> : i === index && !error ? <LoaderCircle className="spin" size={16}/> : <span className="stage-dot"/>}<span>{label}</span>
    </li>)}</ol>
    {error && <div role="alert" className="error-panel"><ShieldAlert size={18}/>{error}<button onClick={() => { setError(""); setStage("url"); setAttempt((a) => a + 1); }}>Retry inspection</button></div>}
    {report && <div className={`gate-verdict risk-${report.bundle.risk.toLowerCase()}`}>
      <span className="eyebrow">DETERMINISTIC VERDICT</span><h3>{riskLabels[report.bundle.risk]}</h3>
      <p>{report.bundle.risk === "INCONCLUSIVE" ? "Some mandatory checks are unavailable. Missing intelligence is not evidence of safety." : "Based on collected indicators and coverage. The AI cannot override this verdict."}</p>
      <span className="micro">{report.bundle.provenance.collection.toUpperCase()} EVIDENCE · {report.chain_receipt.mode === "fixture" ? "SIMULATED ANCHOR" : "LOCAL EVM ANCHOR"}</span>
      {report.bundle.evidence.some((e) => e.type === "threat_intel" && e.status === "COMPLETE" && e.data.provider === "google_safe_browsing" && e.data.matched) && <p>This destination may be unsafe; false positives and false negatives are possible. <a href="https://safebrowsing.google.com/" target="_blank" rel="noreferrer">Advisory provided by Google.</a></p>}
    </div>}
    <div className="gate-actions"><button className="button secondary" onClick={onClose}>Block navigation</button>{report && <Link className="button primary" href={`/report/${report.bundle.report_id}`}>Open full Evidence Passport <ArrowUpRight size={16}/></Link>}</div>
    {report && <button className="unsafe-link" disabled={!canProceed} onClick={() => { if (canProceed) window.open(report.bundle.normalized_url, "_blank", "noopener,noreferrer"); }}>Proceed anyway (unsafe){input.fixture_id ? " — disabled for demo fixtures" : ssrf ? " — private destination blocked" : ""}</button>}
  </dialog>;
}
