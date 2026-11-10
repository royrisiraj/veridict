"""Deterministic fixtures are explicit inputs, never replacements for live failures."""
import json
from pathlib import Path
from app.config import ROOT
from app.models import FixtureMetadata, InvestigateRequest
from app.security.redact import redact_text, redact_url

FIXTURE_IDS = tuple([f"suspicious-{i}" for i in range(1, 4)] + [f"benign-{i}" for i in range(1, 4)])
PACKAGED = Path(__file__).resolve().parent / "demo" / "inputs"


def load_fixture(fixture_id: str) -> dict:
    if fixture_id not in FIXTURE_IDS:
        raise LookupError("Fixture not found")
    source = ROOT / "fixtures" / f"{fixture_id}.json"
    if not source.is_file():
        source = PACKAGED / f"{fixture_id}.json"
    return json.loads(source.read_text(encoding="utf-8"))


def fixture_metadata() -> list[FixtureMetadata]:
    result = []
    for fixture_id in FIXTURE_IDS:
        fixture = load_fixture(fixture_id)
        result.append(FixtureMetadata(fixture_id=fixture_id, title=fixture["title"], expected_risk=fixture["expected_risk"], input=InvestigateRequest(
            url=redact_url(fixture["input"]["url"]), message=redact_text(fixture["input"]["message"]), fixture_id=fixture_id)))
    return result
