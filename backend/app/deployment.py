"""Read-only serverless fixture passports and independent packaged reference roots.

These references are release assets, not blockchain attestations. No process-local
registration, filesystem writes, or external service is needed at request time.
"""
import json
import re
from pathlib import Path

from app.canonical import keccak256
from app.chain.registry import Anchor, AnchorUnavailableError
from app.models import InvestigationReport

ASSET_ROOT = Path(__file__).resolve().parent / "demo"


def fixture_report_id(fixture_id: str) -> str:
    return "0x" + keccak256(("veridict:demo-fixture:" + fixture_id).encode()).hex()


class FixtureReportStore:
    def __init__(self, root: Path = ASSET_ROOT):
        self.root = root

    def get(self, report_id: str) -> InvestigationReport | None:
        if not re.fullmatch(r"0x[0-9a-f]{64}", report_id):
            return None
        path = self.root / "reports" / f"{report_id}.json"
        if not path.is_file():
            return None
        return InvestigationReport.model_validate_json(path.read_text(encoding="utf-8"))

    def save(self, report):
        raise AnchorUnavailableError("This deployment has read-only fixture reports")

    def close(self):
        return None


class FixtureRegistry:
    mode = "fixture"
    address = ""
    connected = False
    health_connected = False

    def __init__(self, root: Path = ASSET_ROOT):
        self.path = root / "reference-roots.json"

    def register(self, report_id, root):
        raise AnchorUnavailableError("Public-chain registration is disabled in demo fixture mode")

    def read(self, report_id: str) -> Anchor:
        try:
            records = json.loads(self.path.read_text(encoding="utf-8"))
            record = records[report_id]
            return Anchor(record["root"], record["schema_hash"], record["timestamp"])
        except (OSError, ValueError, KeyError, TypeError):
            raise AnchorUnavailableError("Packaged reference root unavailable") from None


class UnavailableRegistry:
    mode = "unavailable"
    address = ""
    connected = False
    health_connected = False

    def register(self, *args):
        raise AnchorUnavailableError("Registry unavailable")

    def read(self, *args):
        raise AnchorUnavailableError("Registry unavailable")
