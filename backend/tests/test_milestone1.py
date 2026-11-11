"""Milestone 1 smoke tooling uses actual store interfaces with an explicit fake provider."""
import pytest
from app.deployment import FixtureReportStore, fixture_report_id
from app.storage import ObjectExistsError, StorageUnavailableError
from scripts.storage_smoke import OwnedObjects, save_diagnostic, read_diagnostic
from scripts.dns_diagnostics import observation


class Objects:
    def __init__(self):
        self.data = {}

    def create(self, key, data):
        if key in self.data:
            raise ObjectExistsError("already exists")
        self.data[key] = data
        return "etag-" + key

    def get(self, key):
        return self.data.get(key)

    def delete(self, key, etag):
        assert etag == "etag-" + key
        del self.data[key]


def test_smoke_preserves_source_uses_fixture_provenance_and_only_cleans_owned_objects():
    source = FixtureReportStore().get(fixture_report_id("benign-1"))
    source_json = source.model_dump_json()
    provider = Objects()
    provider.create("reports/existing.json", b"keep me")
    owned = OwnedObjects(provider)
    report = save_diagnostic(owned)
    assert report.bundle.report_id != source.bundle.report_id
    assert report.bundle.provenance.collection == "fixture"
    assert report.chain_receipt.tx_hash is None
    assert len(owned.created) == 2  # Passport and independent immutable reference.
    assert read_diagnostic(provider, report.bundle.report_id, report.merkle.root) == report
    owned.cleanup()
    assert provider.data == {"reports/existing.json": b"keep me"}
    assert FixtureReportStore().get(source.bundle.report_id).model_dump_json() == source_json


def test_smoke_does_not_report_success_on_provider_outage():
    class Unavailable(Objects):
        def create(self, key, data):
            raise StorageUnavailableError("unavailable")
    with pytest.raises(StorageUnavailableError):
        save_diagnostic(OwnedObjects(Unavailable()))


def test_dns_diagnostics_retains_ip_validation_and_sanitizes_errors():
    assert observation(lambda: ["127.0.0.1"])["status"] == "FAILED"
    assert observation(lambda: ["93.184.216.34"])["status"] == "COMPLETE"
    def failure():
        raise OSError("CANARY_PRIVATE_INFORMATION")
    assert observation(failure) == {"status": "FAILED", "error_type": "OSError"}


def test_preview_smoke_bypass_headers_are_origin_scoped(monkeypatch):
    import runpy
    import httpx
    from pathlib import Path
    helpers = runpy.run_path(str(Path(__file__).resolve().parents[2] / "scripts/deployment_smoke.py"))
    monkeypatch.setenv("FRONTEND_PROTECTION_BYPASS", "frontend-canary")
    monkeypatch.setenv("BACKEND_PROTECTION_BYPASS", "backend-canary")
    for url, expected in [("https://front.example/api/fixtures", "frontend-canary"),
        ("https://back.example/health", "backend-canary"), ("https://other.example/", None),
        ("https://front.example.attacker.example/", None), ("http://front.example/", None)]:
        request = httpx.Request("GET", url)
        helpers["protection_headers"](request, "https://front.example", "https://back.example")
        assert request.headers.get("x-vercel-protection-bypass") == expected
