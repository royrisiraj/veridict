import json
import pytest
from app.security import ssrf, redirects
from app.security.redact import redact_url, redact_text, extract_message_spans
from app.security.url import normalize_url


@pytest.mark.parametrize("ip", ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.2", "169.254.169.254", "::1", "fe80::1", "fc00::1", "::ffff:127.0.0.1", "0.0.0.0", "::", "224.0.0.1", "240.0.0.1", "2001:db8::1"])
def test_nonpublic_addresses_are_blocked(ip):
    with pytest.raises(ssrf.SSRFBlockedError):
        ssrf.validate_public_destination(ip)


def test_mixed_dns_answer_is_rejected(monkeypatch):
    monkeypatch.setattr(ssrf, "resolve_addresses", lambda host: ["93.184.216.34", "10.0.0.2"])
    with pytest.raises(ssrf.SSRFBlockedError):
        ssrf.validate_public_destination("mixed.example")


@pytest.mark.parametrize("url", ["file:///etc/passwd", "gopher://public.example/", "http://user:password@public.example/", "http://public.example\\@127.0.0.1"])
def test_disallowed_network_url_shapes(url):
    with pytest.raises((ssrf.SSRFBlockedError, ValueError)):
        normalized = normalize_url(url)
        # Normalization intentionally strips userinfo; direct networking never accepts it.
        ssrf.destination(url)


async def test_redirect_to_private_ip_is_blocked_before_connect(monkeypatch):
    calls = []
    monkeypatch.setattr(ssrf, "resolve_addresses", lambda host: ["93.184.216.34"])
    async def fake_fetch(url, host, addresses):
        calls.append(host)
        return 302, "http://169.254.169.254/latest/meta-data"
    monkeypatch.setattr(redirects, "fetch_location", fake_fetch)
    result = await redirects.inspect_redirects("https://public.example")
    assert result.data.ssrf_blocked and result.status == "FAILED"
    assert calls == ["public.example"]


async def test_dns_rebinding_cannot_change_the_connected_ip(monkeypatch):
    resolutions = []
    def resolve(host):
        resolutions.append(host)
        return ["93.184.216.34"] if len(resolutions) == 1 else ["127.0.0.1"]
    monkeypatch.setattr(ssrf, "resolve_addresses", resolve)
    addresses = ssrf.validate_public_destination("public.example")
    pinned = ssrf.PinnedBackend("public.example", addresses)
    connected = []
    class Stream:
        def get_extra_info(self, name):
            return ("93.184.216.34", 443)
        async def aclose(self):
            return None
    async def connect(host, *args):
        connected.append(host)
        return Stream()
    monkeypatch.setattr(pinned.backend, "connect_tcp", connect)
    await pinned.connect_tcp("public.example", 443)
    assert resolutions == ["public.example"]
    assert connected == ["93.184.216.34"]


async def test_peer_mismatch_is_closed(monkeypatch):
    pinned = ssrf.PinnedBackend("public.example", ["93.184.216.34"])
    closed = []
    class Stream:
        def get_extra_info(self, name):
            return ("127.0.0.1", 443)
        async def aclose(self):
            closed.append(True)
    async def connect(*args):
        return Stream()
    monkeypatch.setattr(pinned.backend, "connect_tcp", connect)
    with pytest.raises(ssrf.SSRFBlockedError):
        await pinned.connect_tcp("public.example", 443)
    assert closed


async def test_redirect_limit_loop_and_timeout(monkeypatch):
    monkeypatch.setattr(ssrf, "resolve_addresses", lambda host: ["93.184.216.34"])
    async def many(url, host, addresses):
        index = int(url.rsplit("/", 1)[-1])
        return 302, f"https://host{index+1}.example/{index+1}"
    monkeypatch.setattr(redirects, "fetch_location", many)
    result = await redirects.inspect_redirects("https://host0.example/0")
    assert result.data.limit_reached and len(result.data.chain) == 5
    async def loop(url, host, addresses):
        return 302, url
    monkeypatch.setattr(redirects, "fetch_location", loop)
    result = await redirects.inspect_redirects("https://public.example/")
    assert result.data.loop_detected
    async def timeout(*args):
        raise TimeoutError()
    monkeypatch.setattr(redirects, "fetch_location", timeout)
    assert (await redirects.inspect_redirects("https://public.example/")).status == "TIMEOUT"


def test_redaction_removes_secrets_and_userinfo():
    raw = "https://alice:CANARY_PASSWORD@public.example/path?session_token=CANARY_TOKEN&api_key=CANARY_KEY&normal=visible#access_token=CANARY_FRAGMENT"
    redacted = redact_url(raw)
    assert "CANARY" not in redacted and "alice" not in redacted
    assert "normal=visible" in redacted and "[REDACTED]" in redacted
    assert redact_url(redacted) == redacted
    assert "aB3cD4eF5gH6iJ7kL8mN9pQ0r" not in redact_url("https://public.example/?value=aB3cD4eF5gH6iJ7kL8mN9pQ0r")


def test_message_pii_seeds_and_secrets_are_masked():
    raw = "URGENT password=CANARY_PASS email alice@example.com phone +1 202 555 0199 card 4111 1111 1111 1111 seed phrase: alpha beta gamma delta echo foxtrot golf hotel india juliet kilo lima"
    encoded = json.dumps([e.model_dump() for e in extract_message_spans(raw)])
    for secret in ["CANARY_PASS", "alice@example.com", "202 555", "4111", "alpha beta"]:
        assert secret not in encoded
    assert all(e.data.end > e.data.start and len(e.data.sha256) == 64 for e in extract_message_spans(raw))


def test_secret_canaries_absent_from_api_sqlite_and_logs(client, caplog):
    response = client.post("/api/investigate", json={"url": "https://public.example/?password=CANARY_QUERY", "message": "URGENT password=CANARY_MSG email alice@example.com"})
    assert response.status_code == 200
    report_id = response.json()["bundle"]["report_id"]
    stored = client.app.state.database.connection.execute("SELECT payload FROM reports WHERE report_id=?", (report_id,)).fetchone()[0]
    for value in [response.text, stored, caplog.text]:
        assert "CANARY_QUERY" not in value and "CANARY_MSG" not in value and "alice@example.com" not in value


def test_idna_and_homograph_normalization():
    normalized = normalize_url("https://раypal.com/path")
    assert normalized.hostname.startswith("xn--") and normalized.homograph_detected
