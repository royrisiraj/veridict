"""Executable judge rehearsal, including direct EVM readback when requested."""
import argparse
import os
import sys
from pathlib import Path

import httpx
from web3 import Web3

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.chain.registry import ABI
from app.canonical import SCHEMA_HASH_HEX

parser = argparse.ArgumentParser()
parser.add_argument("--url", default="http://127.0.0.1:8000")
parser.add_argument("--require-evm", action="store_true")
parser.add_argument("--rpc", default=os.getenv("RPC_URL", "http://127.0.0.1:8545"))
args = parser.parse_args()
with httpx.Client(base_url=args.url, timeout=45, trust_env=False) as client:
    health = client.get("/health")
    health.raise_for_status()
    if args.require_evm:
        assert health.json()["chain_connected"], "A real local EVM registry is required"
    fixtures = client.get("/api/fixtures").json()
    for fixture in fixtures:
        response = client.post("/api/investigate", json=fixture["input"])
        response.raise_for_status()
        report = response.json()
        report_id = report["bundle"]["report_id"]
        assert report["bundle"]["risk"] == fixture["expected_risk"]
        assert report["verification"]["status"] == "SUPPORTED"
        if args.require_evm:
            receipt = report["chain_receipt"]
            assert receipt["mode"] == "evm" and receipt["tx_hash"]
            web3 = Web3(Web3.HTTPProvider(args.rpc, request_kwargs={"timeout": 3}))
            registry = web3.eth.contract(address=Web3.to_checksum_address(receipt["contract_address"]), abi=ABI)
            root, schema, timestamp = registry.functions.reports(bytes.fromhex(report_id[2:])).call()
            assert "0x" + bytes(root).hex() == report["merkle"]["root"]
            assert "0x" + bytes(schema).hex() == SCHEMA_HASH_HEX and timestamp > 0
        for mutation, status in [("tls_cert", "TAMPERED"), ("drop_threat_intel", "NOT_SUPPORTED"), ("alter_redirect", "TAMPERED"), ("unground_ai_claim", "NOT_SUPPORTED")]:
            result = client.post(f"/api/reports/{report_id}/tamper-demo", json={"mutation": mutation})
            result.raise_for_status()
            assert result.json()["verification"]["status"] == status
            assert not result.json()["verification"]["root_match"]
        assert client.get(f"/api/reports/{report_id}").json() == report
        assert client.post(f"/api/reports/{report_id}/verify", json={}).json()["status"] == "SUPPORTED"
        print(f"{fixture['fixture_id']}: {report['bundle']['risk']}; seal, 4 mutations and reset verified")
print("Rehearsal passed: 6 reports, 24 mutations, 6 clean resets" + (", direct EVM readback" if args.require_evm else ""))
