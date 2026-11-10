import pytest
from fastapi.testclient import TestClient
from app.chain.registry import MemoryRegistry
from app.config import Settings
from app.main import create_app


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(database_path=str(tmp_path / "reports.db"), chain_mode="fixture", live_checks=False, openai_key="", openai_model=""), MemoryRegistry())
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def report(client):
    fixture = client.get("/api/fixtures").json()[0]
    response = client.post("/api/investigate", json=fixture["input"])
    assert response.status_code == 200
    return response.json()
