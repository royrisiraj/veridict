"""Emit verified existing passport vectors without changing any report bytes."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.canonical import SCHEMA_HASH_HEX, canonical_json
from app.deployment import FixtureReportStore, fixture_report_id
from app.fixtures import FIXTURE_IDS
from app.sealing import seal_bundle

results = []
store = FixtureReportStore()
for fixture in FIXTURE_IDS:
    report = store.get(fixture_report_id(fixture))
    if report is None:
        raise SystemExit("Missing packaged passport")
    recomputed = seal_bundle(report.bundle)
    if recomputed.model_dump() != report.merkle.model_dump():
        raise SystemExit("Packaged passport Merkle mismatch")
    results.append({"report_id": report.bundle.report_id, "root": recomputed.root, "schema_hash": SCHEMA_HASH_HEX,
        "leaves": [{"id": leaf.id, "type": leaf.type, "hash": leaf.hash, "canonical": canonical_json(leaf.payload).decode()} for leaf in recomputed.leaves],
        "proofs_by_id": recomputed.proofs_by_id})
print(json.dumps(results, ensure_ascii=True))
