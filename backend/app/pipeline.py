"""Collect -> redact -> classify -> explain -> seal -> anchor -> verify -> persist."""
import asyncio
import ipaddress
from datetime import datetime, timezone
from uuid import uuid4
from urllib.parse import urlsplit

from app.ai.analyzer import analyze
from app.canonical import keccak256
from app.fixtures import load_fixture
from app.intel.openphish import lookup_openphish
from app.intel.safebrowsing import lookup_safebrowsing
from app.models import (ChainReceipt, CoverageMap, EvidenceBundle, InvestigationReport, Provenance, RedirectData, RedirectEvidence,
    ThreatData, ThreatEvidence, TLSData, TLSEvidence, URLEvidence, URLData, VerificationResponse)
from app.risk import classify
from app.sealing import seal_bundle
from app.security.redact import extract_message_spans, redact_text, redact_url
from app.security.redirects import inspect_redirects
from app.security.ssrf import SSRFBlockedError, validate_ip
from app.security.tls import inspect_tls
from app.security.url import normalize_url

STAGES = ["url", "redirects", "tls", "threat_intel", "ai", "seal"]


async def investigate(request, settings, database, registry, verifier, emit, report_id: str | None = None, seal_only: bool = False):
    fixture = load_fixture(request.fixture_id) if request.fixture_id else None
    if fixture and normalize_url(request.url).normalized_url != normalize_url(fixture["input"]["url"]).normalized_url:
        raise ValueError("Fixture input URL does not match the selected fixture")
    raw_url = fixture["input"]["url"] if fixture else request.url
    raw_message = fixture["input"]["message"] if fixture else request.message or ""
    if not fixture and settings.live_checks:
        submitted = urlsplit(raw_url)
        if submitted.username is not None or submitted.password is not None:
            raise ValueError("Credential-bearing scan destinations are prohibited")
    mode = "fixture" if fixture else ("live" if settings.live_checks else "local")
    created = "2026-11-10T12:00:00Z" if fixture else datetime.now(timezone.utc).isoformat()
    await emit("url")
    normalized = normalize_url(raw_url)
    if fixture:
        url_values = dict(fixture["simulated_checks"]["url"])
        url_values.pop("status", None)
        normalized = URLData(**{**normalized.model_dump(), **url_values})
    evidence = [URLEvidence(id="url:1", status="COMPLETE", mode=mode, data=normalized)]
    evidence.extend(extract_message_spans(raw_message, mode))
    # Only the redacted URL is used in network collection and external intelligence.
    safe_url = normalized.normalized_url
    await emit("redirects")
    if fixture:
        values = dict(fixture["simulated_checks"]["redirects"])
        status = values.pop("status")
        values["chain"] = [redact_url(u) for u in values["chain"]]
        redirect = RedirectEvidence(id="redir:1", status=status, mode="fixture", data=RedirectData(**values))
    elif settings.live_checks:
        redirect = await inspect_redirects(safe_url, allowed_hosts=settings.scan_allowed_hosts or None)
    else:
        blocked = False
        try:
            address = ipaddress.ip_address(normalized.hostname)
        except ValueError:
            blocked = normalized.hostname in {"localhost", "localhost.localdomain"} or normalized.hostname.endswith(".localhost")
        else:
            try:
                validate_ip(str(address))
            except SSRFBlockedError:
                blocked = True
        redirect = RedirectEvidence(id="redir:1", status="FAILED" if blocked else "INCOMPLETE", mode="local", data=RedirectData(chain=[safe_url], ssrf_blocked=blocked))
    evidence.append(redirect)
    await emit("tls")
    if fixture:
        values = dict(fixture["simulated_checks"]["tls"])
        status = values.pop("status")
        tls = TLSEvidence(id="tls:1", status=status, mode="fixture", data=TLSData(**values))
    elif settings.live_checks and not redirect.data.ssrf_blocked and urlsplit(safe_url).scheme == "https":
        tls = await inspect_tls(normalized.hostname, urlsplit(safe_url).port or 443)
    else:
        tls = TLSEvidence(id="tls:1", status="INCOMPLETE", mode=mode, data=TLSData())
    evidence.append(tls)
    await emit("threat_intel")
    if fixture:
        values = dict(fixture["simulated_checks"]["threat_intel"])
        status = values.pop("status")
        if status != "COMPLETE":
            values["matched"] = None
        threat = ThreatEvidence(id="ti:1", status=status, mode="fixture", data=ThreatData(**values))
        evidence.append(threat)
    elif settings.live_checks:
        threat = await lookup_openphish(safe_url, settings)
        evidence.append(threat)
        evidence.append(await lookup_safebrowsing(safe_url, settings.safe_browsing_key))
    else:
        threat = ThreatEvidence(id="ti:1", status="INCOMPLETE", mode="local", data=ThreatData(provider="openphish", queried_at=created))
        evidence.append(threat)
    coverage = CoverageMap(url="COMPLETE", tls=tls.status, threat_intel=threat.status, redirects=redirect.status)
    risk = classify(evidence, coverage)
    await emit("ai")
    analysis, analyzer_mode = await analyze(evidence, settings, fixture=bool(fixture))
    bundle = EvidenceBundle(report_id=report_id or "0x" + keccak256(uuid4().bytes).hex(), created_at=created,
        normalized_url=safe_url, risk=risk, evidence=evidence, ai_claims=analysis.claims, coverage=coverage,
        provenance=Provenance(collection=mode, analyzer=analyzer_mode, fixture_id=request.fixture_id),
        social_engineering_indicators=analysis.social_engineering_indicators, limitations=analysis.limitations)
    await emit("seal")
    merkle = seal_bundle(bundle)
    if seal_only:
        await asyncio.to_thread(database.save_reference, bundle, merkle)
        receipt = ChainReceipt(tx_hash=None, block_number=None, contract_address=None, network="sealed-not-anchored", mode="unanchored")
    else:
        receipt = await asyncio.to_thread(registry.register, bundle.report_id, merkle.root)
    # Verification uses a provisional report solely for original proofs/source; it still reads the independent anchor.
    provisional = InvestigationReport.model_construct(bundle=bundle, merkle=merkle, chain_receipt=receipt)
    verification = await asyncio.to_thread(verifier.verify_bundle, bundle.report_id, bundle, None, provisional)
    if verification.status != "SUPPORTED":
        raise RuntimeError("Newly sealed report did not independently verify")
    report = InvestigationReport(bundle=bundle, merkle=merkle, chain_receipt=receipt, verification=verification)
    await asyncio.to_thread(database.save, report)
    return report
