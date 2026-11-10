import json
import pytest
from app.config import Settings
from app.main import create_app
from app.chain.registry import MemoryRegistry
from fastapi.testclient import TestClient


def test_all_six_fixtures_are_sealed_and_retrievable(client):
    fixtures = client.get("/api/fixtures").json()
    assert len(fixtures) == 6
    assert "secret_abc123" not in json.dumps(fixtures)
    for fixture in fixtures:
        response = client.post("/api/investigate", json=fixture["input"])
        assert response.status_code == 200, response.text
        report = response.json()
        assert report["bundle"]["risk"] == fixture["expected_risk"]
        assert report["bundle"]["provenance"]["collection"] == "fixture"
        assert report["verification"]["status"] == "SUPPORTED"
        assert report["chain_receipt"]["tx_hash"] is None
        report_id = report["bundle"]["report_id"]
        assert client.get(f"/api/reports/{report_id}").json() == report
        assert client.post(f"/api/reports/{report_id}/verify", json={}).json()["status"] == "SUPPORTED"


def test_custom_offline_url_has_unknown_checks(client):
    response = client.post("/api/investigate", json={"url": "https://ordinary.example/", "message": "Action Required: Server Maintenance"})
    bundle = response.json()["bundle"]
    assert bundle["risk"] == "INCONCLUSIVE"
    assert bundle["coverage"]["threat_intel"] == "INCOMPLETE"
    assert next(e for e in bundle["evidence"] if e["type"] == "threat_intel")["data"]["matched"] is None


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://169.254.169.254/latest", "http://[::1]/", "http://localhost/"])
def test_offline_ssrf_is_locally_recognized(client, url):
    response = client.post("/api/investigate", json={"url": url})
    assert response.status_code == 200
    assert response.json()["bundle"]["risk"] == "HIGH_RISK"


def test_sse_progress_and_json_have_same_contract(client):
    fixture = client.get("/api/fixtures").json()[0]
    response = client.post("/api/investigate", json=fixture["input"], headers={"Accept": "text/event-stream"})
    events = response.text.strip().split("\n\n")
    stages = [json.loads(e.split("data: ")[1])["stage"] for e in events if e.startswith("event: stage")]
    assert stages == ["url", "redirects", "tls", "threat_intel", "ai", "seal"]
    final = json.loads(events[-1].split("data: ")[1])
    assert final["verification"]["status"] == "SUPPORTED"


def test_sse_failure_keeps_navigation_blocked(client):
    response = client.post("/api/investigate", json={"url": "file:///private"}, headers={"Accept": "text/event-stream"})
    assert "event: error" in response.text
    assert "event: report" not in response.text


def test_unknown_and_invalid_requests_are_sanitized(client):
    assert client.get("/api/reports/missing").status_code == 404
    response = client.post("/api/investigate", json={"url": "https://x.example", "message": "SECRET_CANARY", "bad": "SECRET_CANARY"})
    assert response.status_code == 422 and "SECRET_CANARY" not in response.text
    assert client.post("/api/investigate", json={"url": "https://x.example", "fixture_id": "../private"}).status_code == 404
    assert client.post("/api/investigate", json={"url": "https://x.example", "fixture_id": "benign-1"}).status_code == 422


def test_restart_does_not_reconstruct_simulated_anchor_from_report(tmp_path):
    settings = Settings(database_path=str(tmp_path / "db.sqlite"), chain_mode="fixture", live_checks=False, openai_key="", openai_model="")
    with TestClient(create_app(settings, MemoryRegistry())) as first:
        report = first.post("/api/investigate", json={"url": "https://ordinary.example/"}).json()
    with TestClient(create_app(settings, MemoryRegistry())) as second:
        report_id = report["bundle"]["report_id"]
        assert second.get(f"/api/reports/{report_id}").status_code == 200
        assert second.post(f"/api/reports/{report_id}/verify", json={}).status_code == 503


def test_health_labels_memory_mode(client):
    state = client.get("/health").json()
    assert state["status"] == "ok" and state["chain_mode"] == "fixture"
    assert not state["chain_connected"] and state["contract_address"] == ""
    assert state["verification_mode"] == "LOCAL_DEVELOPMENT"
