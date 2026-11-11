"""Private Blob passport persistence check, with no live collection or chain access.

Default cleanup removes only the unique objects created by this run. --keep-report
retains the explicitly fixture-based diagnostic passport for Preview API checks.
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.canonical import keccak256
from app.deployment import FixtureReportStore, fixture_report_id
from app.models import ChainReceipt
from app.production import ProductionVerifier
from app.sealing import seal_bundle
from app.storage import BlobReportStore, PrivateBlobObjects, report_key


def diagnostic_passport():
    source = FixtureReportStore().get(fixture_report_id("benign-1"))
    report = source.model_copy(deep=True)
    report.bundle.report_id = "0x" + keccak256(("veridict:storage-smoke:" + uuid4().hex).encode()).hex()
    report.bundle.limitations.append("Storage diagnostic cloned from benign-1 fixture; no live collection or public-chain anchoring.")
    report.merkle = seal_bundle(report.bundle)
    report.chain_receipt = ChainReceipt(tx_hash=None, block_number=None, contract_address=None,
        network="sealed-not-anchored", mode="unanchored")
    return report


class OwnedObjects:
    """Track only successful creates from this run for conditional cleanup."""
    def __init__(self, provider):
        self.provider = provider
        self.created = []

    def get(self, key):
        return self.provider.get(key)

    def create(self, key, data):
        etag = self.provider.create(key, data)
        self.created.append((key, etag))
        return etag

    def cleanup(self):
        for key, etag in reversed(self.created):
            self.provider.delete(key, etag)


def save_diagnostic(objects):
    report = diagnostic_passport()
    store = BlobReportStore(objects)
    store.save_reference(report.bundle, report.merkle)
    report.verification = ProductionVerifier(store).verify_bundle(report.bundle.report_id, report.bundle, genuine=report)
    if report.verification.status != "SUPPORTED":
        raise RuntimeError("Diagnostic reference did not verify")
    store.save(report)
    return report


def read_diagnostic(objects, report_id, expected_root):
    report_key(report_id)
    report_key(expected_root)
    store = BlobReportStore(objects)
    report = store.get(report_id)
    if report is None or report.merkle.root != expected_root or seal_bundle(report.bundle) != report.merkle:
        raise RuntimeError("Persistence readback differs")
    if report.bundle.provenance.collection != "fixture" or report.chain_receipt.mode != "unanchored":
        raise RuntimeError("Diagnostic provenance differs")
    checked = ProductionVerifier(store).verify_bundle(report_id, report.bundle)
    if checked.status != "SUPPORTED" or checked.public_chain_status != "NOT_CONFIGURED":
        raise RuntimeError("Independent reference verification failed")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--keep-report", action="store_true")
    parser.add_argument("--read-report", metavar="REPORT_ID")
    parser.add_argument("--expected-root")
    args = parser.parse_args()
    if args.read_report:
        if not args.expected_root or args.keep_report:
            parser.error("Read mode requires --expected-root and does not accept --keep-report")
        read_diagnostic(PrivateBlobObjects(), args.read_report, args.expected_root)
        print("PASS separate-process private passport/reference readback and Merkle/grounding verification")
        return
    if args.expected_root:
        parser.error("--expected-root is only valid with --read-report")
    owned = OwnedObjects(PrivateBlobObjects())
    succeeded = False
    try:
        print("Writing unique, fixture-labelled diagnostic passport and independent reference...", flush=True)
        report = save_diagnostic(owned)
        result = subprocess.run([sys.executable, str(Path(__file__).resolve()), "--read-report", report.bundle.report_id,
            "--expected-root", report.merkle.root], capture_output=True, text=True, timeout=120, check=False)
        if result.returncode != 0:
            raise RuntimeError("Separate-process storage readback failed")
        print(result.stdout.strip())
        succeeded = True
        print(json.dumps({"report_id": report.bundle.report_id, "root": report.merkle.root,
            "evidence_mode": "fixture", "public_chain": "NOT_CONFIGURED", "retained": args.keep_report}))
    finally:
        if not args.keep_report or not succeeded:
            owned.cleanup()
            print("Removed only diagnostic objects created by this run.")
        else:
            print("Diagnostic passport retained for Preview API/permalink validation; no live evidence is claimed.")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        raise SystemExit("Storage smoke failed; persistence is NOT confirmed. Inspect authentication, connectivity and any diagnostic objects privately.") from None
