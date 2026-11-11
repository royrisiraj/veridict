"""Explicit real-provider preflight. Never deploys, signs or registers a root."""
import argparse
import asyncio
import json
import sys
from pathlib import Path
from uuid import uuid4
from urllib.parse import urlsplit
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.chain.sepolia import SepoliaRegistry
from app.config import Settings
from app.deployment import FixtureReportStore, fixture_report_id
from app.fixtures import FIXTURE_IDS
from app.intel.openphish import lookup_openphish
from app.security.redirects import inspect_redirects
from app.security.ssrf import validate_public_destination
from app.security.tls import inspect_tls
from app.storage import PrivateBlobObjects


async def collect(url):
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username is not None or parts.password is not None or (parts.port or 443) != 443 or parts.query or parts.fragment:
        raise ValueError("Probe requires a non-sensitive, credential-free public HTTPS URL without query or fragment")
    addresses = await asyncio.to_thread(validate_public_destination, parts.hostname)
    redirect = await inspect_redirects(url, allowed_hosts=(parts.hostname,))
    tls = await inspect_tls(parts.hostname)
    threat = await lookup_openphish(url, Settings(runtime_mode="serverless", live_checks=True))
    print(json.dumps({"dns_public_addresses": addresses, "redirects": redirect.model_dump(), "tls": tls.model_dump(), "threat_intel": threat.model_dump()}, indent=2))
    return redirect.status == "COMPLETE" and tls.status == "COMPLETE"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--collect", metavar="HTTPS_URL")
    parser.add_argument("--chain", action="store_true")
    parser.add_argument("--storage-write-check", action="store_true", help="Create, retrieve through a fresh client, and remove a private probe object")
    args = parser.parse_args()
    if args.collect and not asyncio.run(collect(args.collect)):
        raise SystemExit("Real collection did not complete; no successful live check is asserted")
    if args.chain:
        chain = SepoliaRegistry(Settings())
        chain.check()
        print("RPC confirmed chain 11155111, bytecode and registry ABI")
        for fixture in FIXTURE_IDS:
            report = FixtureReportStore().get(fixture_report_id(fixture))
            status = chain.status(report.bundle.report_id, report.merkle.root, FixtureReportStore())
            print(f"{fixture}: {status.status}")
            if status.status not in {"VERIFIED", "NOT_ANCHORED"}:
                raise SystemExit("Fixture public-chain check failed")
    if args.storage_write_check:
        key = f"probes/{uuid4().hex}.json"
        original = b'{"service":"veridict","probe":true}'
        objects = PrivateBlobObjects()
        etag = objects.create(key, original)
        if PrivateBlobObjects().get(key) != original:
            raise SystemExit("Private persistence readback failed")
        objects.delete(key, etag)
        print("Private Blob write and independent-client readback succeeded; probe deleted")
    if not any((args.collect, args.chain, args.storage_write_check)):
        parser.error("Select at least one explicit preflight")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Upstream exception messages can contain credential-bearing URLs.
        raise SystemExit("Provider preflight failed; inspect configuration privately. No successful result is asserted.") from None
