"""The only component allowed to assign a final risk state."""
from app.models import CoverageMap, Evidence, RiskClass


def classify(evidence: list[Evidence], coverage: CoverageMap) -> RiskClass:
    urls = [e.data for e in evidence if e.type == "url"]
    tls = [e.data for e in evidence if e.type == "tls" and e.status == "COMPLETE"]
    redirects = [e.data for e in evidence if e.type == "redirect"]
    patterns = {e.data.pattern_type for e in evidence if e.type == "message_span"}
    credential = bool(patterns & {"credential_harvesting", "otp_request", "seed_phrase_request"})
    typo = any(u.typosquat_target or u.homograph_detected for u in urls)
    confirmed = any(u.confirmed_impersonation for u in urls)
    invalid_tls = any(t.hostname_ok is False or t.expired is True or t.trusted is False for t in tls)
    tls_failure = any(t.hostname_ok is False or t.expired is True for t in tls)
    brand = any(u.brand_impersonation for u in urls) or "brand_impersonation" in patterns
    cross_domain = any(r.untrusted_destination for r in redirects)
    if any(e.type == "threat_intel" and e.status == "COMPLETE" and e.data.matched is True for e in evidence) or (confirmed and invalid_tls and credential):
        return RiskClass.CONFIRMED_MALICIOUS
    if typo or (brand and (credential or cross_domain or tls_failure)) or any(r.ssrf_blocked for r in redirects):
        return RiskClass.HIGH_RISK
    if (any(t.self_signed is True or t.expired is True or t.trusted is False or t.hostname_ok is False for t in tls)
        or any(r.cross_domain_hops > 2 or r.loop_detected or r.limit_reached for r in redirects)
        or (any(u.suspicious_tld for u in urls) and "urgency" in patterns)
        or any(u.obfuscated for u in urls)):
        return RiskClass.SUSPICIOUS
    if any(value != "COMPLETE" for value in coverage.model_dump().values()):
        return RiskClass.INCONCLUSIVE
    return RiskClass.LOW_RISK
