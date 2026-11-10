"""Serverless readiness without writable storage, shared processes or live services."""
import copy
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from app.config import Settings
from app.deployment import FixtureRegistry, FixtureReportStore, fixture_report_id
from app.fixtures import FIXTURE_IDS
from app.main import create_app


def hosted_app(**overrides):
    return create_app(Settings(runtime_mode="serverless", chain_mode="demo_fixture", live_checks=False, openai_key="", openai_model="", **overrides))


def test_health_no_database_rpc_or_live_service(monkeypatch):
    import app.main as main
    def prohibited(*args):
        raise AssertionError("Serverless preview must not create SQLite or an EVM connection")
    monkeypatch.setattr(main, "Database", prohibited)
    monkeypatch.setattr(main, "create_registry", prohibited)
    with TestClient(hosted_app(database_path="/read-only/not-writable/reports.db")) as client:
        health = client.get("/health").json()
        assert health["service"] == "veridict-api" and health["version"] == "1"
        assert health["verification_mode"] == "DEMO_FIXTURE"
        assert not health["chain_connected"] and not health["live_scanning_enabled"]
        assert health["report_storage"] == "packaged-read-only"


def test_all_fixture_passports_survive_new_app_instances():
    ids = []
    with TestClient(hosted_app()) as client:
        fixtures = client.get("/api/fixtures").json()
        assert len(fixtures) == 6
        for fixture in fixtures:
            response = client.post("/api/investigate", json=fixture["input"])
            assert response.status_code == 200, response.text
            report = response.json()
            assert report["bundle"]["risk"] == fixture["expected_risk"]
            assert report["verification"]["status"] == "SUPPORTED"
            assert report["chain_receipt"]["network"] == "fixture-sealed-assets"
            assert report["chain_receipt"]["tx_hash"] is None
            ids.append(report["bundle"]["report_id"])
    # Entirely different lifespan/registry; no memory or SQLite carries the root/report.
    with TestClient(hosted_app()) as cold:
        for report_id in ids:
            assert cold.get(f"/api/reports/{report_id}").status_code == 200
            assert cold.post(f"/api/reports/{report_id}/verify", json={}).json()["status"] == "SUPPORTED"


@pytest.mark.parametrize("mutation,status", [("tls_cert", "TAMPERED"), ("drop_threat_intel", "NOT_SUPPORTED"), ("alter_redirect", "TAMPERED"), ("unground_ai_claim", "NOT_SUPPORTED")])
def test_read_only_tamper_and_reset(mutation, status):
    report_id = fixture_report_id("suspicious-1")
    with TestClient(hosted_app()) as client:
        original = client.get(f"/api/reports/{report_id}").json()
        candidate = client.post(f"/api/reports/{report_id}/tamper-demo", json={"mutation": mutation}).json()
        assert candidate["verification"]["status"] == status
        assert not candidate["verification"]["root_match"]
    with TestClient(hosted_app()) as cold:
        assert cold.get(f"/api/reports/{report_id}").json() == original
        assert cold.post(f"/api/reports/{report_id}/verify", json={}).json()["status"] == "SUPPORTED"


def test_fixture_integrity_requires_separate_trusted_manifest(tmp_path):
    from app.verifier import Verifier
    store = FixtureReportStore()
    report = store.get(fixture_report_id("benign-1"))
    verifier = Verifier(store, FixtureRegistry(tmp_path))
    from app.chain.registry import AnchorUnavailableError
    with pytest.raises(AnchorUnavailableError):
        verifier.verify_bundle(report.bundle.report_id, report.bundle)


def test_no_custom_public_scanning_and_size_limit():
    with TestClient(hosted_app()) as client:
        assert client.post("/api/investigate", json={"url": "https://ordinary.example/"}).status_code == 403
        assert client.post("/api/investigate", content=b"x" * 524289, headers={"Content-Type": "application/json"}).status_code == 413
        fixture = client.get("/api/fixtures").json()[0]
        response = client.post("/api/investigate", json=fixture["input"], headers={"Accept": "text/event-stream"})
        assert "event: report" in response.text and "fixture-sealed-assets" in response.text


def test_unconfigured_public_chain_is_unavailable_not_memory_fallback():
    with TestClient(create_app(Settings(runtime_mode="serverless", chain_mode="public_chain"))) as client:
        assert client.get("/health").json()["verification_mode"] == "UNAVAILABLE"
        fixture = client.get("/api/fixtures").json()[0]
        assert client.post("/api/investigate", json=fixture["input"]).status_code == 503
        report_id = fixture_report_id("benign-1")
        assert client.post(f"/api/reports/{report_id}/verify", json={}).status_code == 503


def test_packaged_fixtures_load_without_repository_root(monkeypatch, tmp_path):
    import app.fixtures as fixtures
    monkeypatch.setattr(fixtures, "ROOT", tmp_path)
    monkeypatch.chdir(tmp_path)
    assert len(fixtures.fixture_metadata()) == 6
    assert all(fixtures.load_fixture(name)["fixture_id"] == name for name in FIXTURE_IDS)
