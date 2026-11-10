from datetime import datetime, timedelta, timezone
import hashlib
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from app.config import Settings
from app.security import tls
from app.intel import openphish, safebrowsing


def certificate(name="public.example", *, expired=False):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(days=10))
        .not_valid_after(now+timedelta(days=-1 if expired else 10))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False).sign(key, hashes.SHA256()))
    return cert


def test_tls_hostname_and_wildcard_rules():
    assert tls.certificate_matches(certificate("*.public.example"), "one.public.example")
    assert not tls.certificate_matches(certificate("*.public.example"), "two.one.public.example")
    assert not tls.certificate_matches(certificate("public.example"), "evil.example")


async def test_tls_inspection_records_real_certificate_properties(monkeypatch):
    cert = certificate(expired=True)
    der = cert.public_bytes(serialization.Encoding.DER)
    monkeypatch.setattr(tls, "validate_public_destination", lambda host: ["93.184.216.34"])
    monkeypatch.setattr(tls, "read_certificate", lambda *args: der)
    result = await tls.inspect_tls("public.example")
    assert result.status == "COMPLETE" and result.data.expired and result.data.hostname_ok
    assert result.data.self_signed and result.data.cert_sha256 == hashlib.sha256(der).hexdigest()


async def test_tls_timeout_stays_unknown(monkeypatch):
    def timeout(*args):
        raise TimeoutError()
    monkeypatch.setattr(tls, "validate_public_destination", timeout)
    result = await tls.inspect_tls("public.example")
    assert result.status == "TIMEOUT" and result.data.hostname_ok is None


async def test_cached_openphish_hit_miss_and_invalid_cache(tmp_path):
    path = tmp_path / "feed.txt"
    path.write_text("https://listed.example/\n")
    settings = Settings(openphish_cache_path=str(path))
    assert (await openphish.lookup_openphish("https://listed.example/", settings)).data.matched is True
    assert (await openphish.lookup_openphish("https://other.example/", settings)).data.matched is False
    path.write_text("")
    result = await openphish.lookup_openphish("https://other.example/", settings)
    assert result.status == "FAILED" and result.data.matched is None


async def test_optional_safebrowsing_unconfigured_is_unknown():
    result = await safebrowsing.lookup_safebrowsing("https://public.example", "")
    assert result.status == "UNCONFIGURED" and result.data.matched is None


async def test_safebrowsing_caches_negative_result_and_redacts_query(monkeypatch):
    import httpx
    safebrowsing.CACHE.clear()
    captured = []
    async def handler(request):
        captured.append(request)
        assert "CANARY_SECRET" not in str(request.url)
        assert request.headers["X-Goog-Api-Key"] == "test-key"
        return httpx.Response(200, json={"threats": [], "cacheDuration": "300s"})
    real_client = httpx.AsyncClient
    monkeypatch.setattr(safebrowsing.httpx, "AsyncClient", lambda **kwargs: real_client(transport=httpx.MockTransport(handler), **kwargs))
    for _ in range(2):
        result = await safebrowsing.lookup_safebrowsing("https://public.example/?token=CANARY_SECRET", "test-key")
        assert result.status == "COMPLETE" and result.data.matched is False
    assert len(captured) == 1
    assert all("public.example" not in key for key in safebrowsing.CACHE)
    safebrowsing.CACHE.clear()
