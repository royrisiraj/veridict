"""Import real fixture transaction metadata into private Blob after RPC validation.

This performs storage writes only; it cannot sign or broadcast a transaction.
"""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.chain.sepolia import SepoliaRegistry
from app.config import Settings
from app.models import ChainReceipt
from app.storage import BlobReportStore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    args = parser.parse_args()
    chain = SepoliaRegistry(Settings())
    chain.check()
    store = BlobReportStore()
    entries = json.loads(args.manifest.read_text(encoding="utf-8"))
    for report_id, item in entries.items():
        report = store.get(report_id)
        if report is None or item["root"] != report.merkle.root:
            raise SystemExit("Manifest does not match an existing canonical passport")
        receipt = ChainReceipt.model_validate({k: item[k] for k in ChainReceipt.model_fields})
        # Validate the transaction before persisting any receipt metadata.
        candidate = BlobReportStore()
        original_objects = candidate.objects
        class CandidateObjects:
            def get(self, key):
                if key == f"anchors/{report_id}.json":
                    return receipt.model_dump_json().encode()
                return original_objects.get(key)
        candidate.objects = CandidateObjects()
        status = chain.status(report_id, report.merkle.root, candidate)
        if status.status != "VERIFIED" or status.receipt is None:
            raise SystemExit("RPC could not validate registration transaction and root")
        store.put_once(f"anchors/{report_id}.json", status.receipt.model_dump(mode="json"))
        print(f"Stored validated Sepolia receipt: {report_id}")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Receipt import failed; inspect configuration privately. No successful import is asserted.") from None
