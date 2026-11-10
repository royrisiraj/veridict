"""Build reproducible read-only passports using the existing pipeline and crypto.

Run from any working directory. --check verifies committed assets without writing.
No live APIs, RPCs, keys, or new transactions are used.
"""
import argparse
import asyncio
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.canonical import SCHEMA_HASH_HEX
from app.chain.registry import Anchor, MemoryRegistry
from app.config import ROOT, Settings
from app.db import Database
from app.deployment import ASSET_ROOT, fixture_report_id
from app.fixtures import FIXTURE_IDS, fixture_metadata
from app.pipeline import investigate
from app.verifier import Verifier


class BuildRegistry(MemoryRegistry):
    def register(self, report_id, root):
        receipt = super().register(report_id, root)
        self.records[report_id] = Anchor(root, SCHEMA_HASH_HEX, int(datetime(2026, 11, 10, 12, tzinfo=timezone.utc).timestamp()))
        receipt.network = "fixture-sealed-assets"
        return receipt


async def build(check: bool):
    outputs = {}
    for fixture_id in FIXTURE_IDS:
        original = ROOT / "fixtures" / f"{fixture_id}.json"
        if not original.exists():
            raise SystemExit("Packaging requires the repository-root fixture sources")
        outputs[ASSET_ROOT / "inputs" / original.name] = original.read_text(encoding="utf-8")
    database = Database(":memory:")
    registry = BuildRegistry()
    settings = Settings(database_path=":memory:", chain_mode="fixture", runtime_mode="native", live_checks=False, openai_key="", openai_model="")
    verifier = Verifier(database, registry)
    async def emit(stage):
        return None
    try:
        for fixture in fixture_metadata():
            report = await investigate(fixture.input, settings, database, registry, verifier, emit, report_id=fixture_report_id(fixture.fixture_id))
            outputs[ASSET_ROOT / "reports" / f"{report.bundle.report_id}.json"] = json.dumps(report.model_dump(mode="json", by_alias=True), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
        outputs[ASSET_ROOT / "reference-roots.json"] = json.dumps({key: asdict(value) for key, value in registry.records.items()}, indent=2, sort_keys=True) + "\n"
    finally:
        database.close()
    for path, content in outputs.items():
        if check:
            if not path.exists() or path.read_text(encoding="utf-8") != content:
                raise SystemExit(f"Demo asset drift: {path.name}; run scripts/package_demo.py")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
    print(f"{'Checked' if check else 'Packaged'} six reproducible fixture reports, inputs and independent reference roots")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    asyncio.run(build(parser.parse_args().check))
