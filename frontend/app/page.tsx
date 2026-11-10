"use client";
import { useEffect, useState } from "react";
import { Activity, ArrowRight, ArrowUpRight, CheckCheck, ChevronRight, Fingerprint, Globe2, Link2, Mail, MessageSquare, Shield, Terminal, Workflow } from "lucide-react";
import InterceptGate from "@/components/InterceptGate";
import { api } from "@/lib/api";
import { riskLabels, type Fixture, type Health, type InvestigationInput } from "@/lib/types";

export default function Home() {
  const [fixtures, setFixtures] = useState<Fixture[]>([]);
  const [health, setHealth] = useState<Health | null>(null);
  const [error, setError] = useState("");
  const [selection, setSelection] = useState<InvestigationInput | null>(null);
  const [url, setUrl] = useState("");
  const [message, setMessage] = useState("");
  const [filter, setFilter] = useState("all");
  useEffect(() => {
    let active = true;
    Promise.all([api<Fixture[]>("fixtures"), api<Health>("health")]).then(([items, state]) => {
      if (active) { setFixtures(items); setHealth(state); }
    }).catch((e) => { if (active) setError(e.message); });
    return () => { active = false; };
  }, []);
  const shown = fixtures.filter((f) => filter === "all" || f.fixture_id.startsWith(filter));
  return <>
    <section className="hero"><div className="hero-copy">
      <div className="eyebrow hero-eyebrow"><span className="live-dot"/> EVIDENCE BEFORE TRUST</div>
      <h1>Every verdict.<br/>Backed. <span>Sealed.</span><br/>Verifiable.</h1>
      <p>Pause the click. Investigate the destination. Turn security findings into a tamper-evident Evidence Passport.</p>
      <a href="#sandbox" className="button primary">Open investigation desk <ArrowRight size={17}/></a>
    </div><div className="hero-console" aria-label="Evidence pipeline overview">
      <div className="console-top"><span><Terminal size={14}/> VERIDICT / SEAL ENGINE</span><span className="micro">v1.0</span></div>
      <div className="seal-visual"><div className="orbit orbit-one"/><div className="orbit orbit-two"/><span className="orbit-node node-one"/><span className="orbit-node node-two"/><span className="orbit-node node-three"/><div className="seal-core"><Fingerprint size={66} strokeWidth={1.1}/></div><span className="seal-coordinate coord-one">EVIDENCE.ROOT</span><span className="seal-coordinate coord-two">INTEGRITY VERIFIED</span></div>
      <div className="console-line"><CheckCheck size={15}/><span>Collect evidence</span><ChevronRight size={13}/><span>Ground claims</span><ChevronRight size={13}/><strong>Seal & verify</strong></div>
      <div className="console-status"><span className={`live-dot ${error ? "offline" : ""}`}/>{health ? health.chain_connected ? "LOCAL EVM CONNECTED" : "OFFLINE DEMO READY / SIMULATED ANCHOR" : error ? "INSPECTION SERVICE UNAVAILABLE" : "CONNECTING TO INSPECTION SERVICE"}</div>
    </div></section>
    <div className="capability-strip"><span><Globe2 size={17}/> URL + TLS inspection</span><span><Shield size={17}/> Deterministic risk</span><span><Workflow size={17}/> Evidence-grounded AI</span><span><Fingerprint size={17}/> Merkle integrity proofs</span></div>
    <section id="sandbox" className="desk"><div className="section-heading"><div><span className="eyebrow">01 / TRUST//INTERCEPT</span><h2>The investigation desk<span className="lime">.</span></h2><p className="muted">Choose a communication to intercept, or inspect your own destination.</p></div><span className="status-chip"><Activity size={13}/>{fixtures.length} DETERMINISTIC CASES</span></div>
      {error && <div role="alert" className="error-panel">{error}<button onClick={() => window.location.reload()}>Reconnect</button></div>}
      <div className="desk-grid"><div className="fixture-area"><div className="fixture-toolbar"><div className="tabs" role="group" aria-label="Filter communications">{[["all", "All cases"], ["suspicious", "Suspicious"], ["benign", "Benign"]].map(([value, label]) => <button key={value} aria-pressed={filter === value} className={filter === value ? "selected" : ""} onClick={() => setFilter(value)}>{label}</button>)}</div><span className="micro">SANDBOX / NO EXTERNAL NAVIGATION</span></div>
        <div className="fixture-grid">{shown.map((fixture, i) => <article className="fixture-card" key={fixture.fixture_id}>
          <div className="fixture-card-top"><span className="channel-icon">{i % 2 ? <MessageSquare size={16}/> : <Mail size={16}/>}</span><span className="micro">{fixture.fixture_id.toUpperCase()}</span><span className={`fixture-dot ${fixture.fixture_id.startsWith("benign") ? "benign" : "suspicious"}`}/></div>
          <h3>{fixture.title}</h3><p className="message-preview">{fixture.input.message}</p>
          <a className="fixture-link" data-testid={`fixture-${fixture.fixture_id}`} href="#sandbox" onClick={(event) => { event.preventDefault(); setSelection(fixture.input); }} onAuxClick={(event) => { event.preventDefault(); if (event.button === 1) setSelection(fixture.input); }}><Link2 size={13}/><span>{fixture.input.url}</span><ArrowUpRight size={13}/></a>
          <div className="fixture-bottom"><span className="micro">FIXTURE EVIDENCE</span><span className={`expected risk-${fixture.expected_risk.toLowerCase()}`}>{riskLabels[fixture.expected_risk]}</span></div>
        </article>)}</div>
      </div><aside className="custom-scanner"><div className="scanner-heading"><span className="square-icon"><Globe2 size={20}/></span><span className="eyebrow">LIVE INPUT / LOCAL-FIRST</span></div><h3>Inspect a destination</h3><p className="muted">A URL is a starting point. Evidence is the answer.</p>
        <form onSubmit={(event) => { event.preventDefault(); setSelection({ url, message: message || null, fixture_id: null }); }}>
          <label htmlFor="url">DESTINATION URL</label><input id="url" type="url" required maxLength={4096} value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" pattern="https?://.*"/>
          <label htmlFor="message">MESSAGE CONTEXT <span>OPTIONAL</span></label><textarea id="message" rows={5} maxLength={12000} value={message} onChange={(e) => setMessage(e.target.value)} placeholder="Paste the email, SMS, or message that brought you here…"/>
          <button className="button primary full" type="submit">Intercept & investigate <ArrowRight size={16}/></button>
        </form><div className="privacy-note"><Shield size={16}/><p>Secrets and personal data are redacted. Only cryptographic commitments reach the registry.</p></div><div className="coverage-note"><span className="micro">MISSING INTELLIGENCE ≠ SAFETY</span><p>Unavailable live checks produce an inconclusive result unless a risk indicator fires.</p></div>
      </aside></div>
    </section>
    <section className="principle"><span className="eyebrow">02 / SEALED//EVIDENCE</span><h2>Trust the evidence.<br/><span className="muted">Verify the integrity.</span></h2><p>Every claim points to a concrete finding. Every finding belongs to a cryptographic seal. Change either, and verification tells the story.</p></section>
    {selection && <InterceptGate input={selection} onClose={() => setSelection(null)}/>}
  </>;
}
