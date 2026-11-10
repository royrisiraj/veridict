import pytest
from app.fixtures import load_fixture
from app.models import CoverageMap, RedirectEvidence, RedirectData, ThreatEvidence, ThreatData, TLSEvidence, TLSData, URLEvidence
from app.risk import classify
from app.security.url import normalize_url
from app.security.redact import extract_message_spans

COMPLETE = CoverageMap(url="COMPLETE", tls="COMPLETE", threat_intel="COMPLETE", redirects="COMPLETE")


def url(value="https://ordinary.example"):
    return URLEvidence(id="url:1", status="COMPLETE", mode="local", data=normalize_url(value))


@pytest.mark.parametrize("status", ["INCOMPLETE", "TIMEOUT", "FAILED", "UNCONFIGURED"])
@pytest.mark.parametrize("check", ["url", "tls", "threat_intel", "redirects"])
def test_each_missing_check_is_inconclusive(check, status):
    coverage = COMPLETE.model_copy(update={check: status})
    assert classify([url()], coverage) == "INCONCLUSIVE"


def test_complete_clean_and_urgency_only_are_low_risk():
    assert classify([url(), *extract_message_spans("Action Required: Server Maintenance")], COMPLETE) == "LOW_RISK"


def test_typosquat_alone_is_high_risk():
    assert classify([url("https://paypa1.com")], COMPLETE) == "HIGH_RISK"


def test_feed_match_overrides_all_other_signals():
    item = ThreatEvidence(id="ti:1", status="COMPLETE", mode="fixture", data=ThreatData(provider="openphish", matched=True, queried_at="now"))
    assert classify([url(), item], COMPLETE.model_copy(update={"tls": "FAILED"})) == "CONFIRMED_MALICIOUS"


def test_brand_requires_corroboration_and_invalid_tls_can_confirm():
    domain = url()
    domain.data.brand_impersonation = True
    assert classify([domain], COMPLETE) == "LOW_RISK"
    spans = extract_message_spans("Provide your password")
    assert classify([domain, *spans], COMPLETE) == "HIGH_RISK"
    domain.data.confirmed_impersonation = True
    tls = TLSEvidence(id="tls:1", status="COMPLETE", mode="fixture", data=TLSData(hostname_ok=False))
    assert classify([domain, *spans, tls], COMPLETE) == "CONFIRMED_MALICIOUS"


def test_suspicion_overrides_incomplete_and_ssrf_is_high():
    tls = TLSEvidence(id="tls:1", status="COMPLETE", mode="fixture", data=TLSData(self_signed=True))
    assert classify([url(), tls], COMPLETE.model_copy(update={"threat_intel": "TIMEOUT"})) == "SUSPICIOUS"
    redirect = RedirectEvidence(id="redir:1", status="FAILED", mode="fixture", data=RedirectData(chain=["http://x.example"], ssrf_blocked=True))
    assert classify([url(), redirect], COMPLETE) == "HIGH_RISK"
