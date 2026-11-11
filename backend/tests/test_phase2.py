"""Offline production integration tests. EVM/Blob providers here are explicit fakes."""
import hashlib
import json
from dataclasses import replace
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient
from web3.exceptions import TransactionNotFound

from app.canonical import SCHEMA_HASH_HEX, canonical_json
from app.chain.anchoring import AnchorService
from app.chain.registry import Anchor, AnchorUnavailableError
from app.chain.sepolia import SepoliaRegistry
from app.config import Settings
from app.deployment import FixtureReportStore, fixture_report_id
from app.main import create_app
from app.models import AnchorResponse, ChainReceipt, InvestigationReport
from app.production import ProductionVerifier
from app.sealing import seal_bundle
from app.storage import (BlobReportStore, DurableControls, ObjectExistsError,
    PrivateBlobObjects, QuotaExceededError, StorageUnavailableError)


class FakeObjects:
    def __init__(self):
        self.data, self.etags = {}, {}
        self.down = False

    def available(self):
        return not self.down

    def get(self, key):
        if self.down:
            raise StorageUnavailableError("offline")
        return self.data.get(key)

    def create(self, key, data):
        if self.down:
            raise StorageUnavailableError("offline")
        if key in self.data:
            raise ObjectExistsError("exists")
        self.data[key] = data
        self.etags[key] = hashlib.sha256(data).hexdigest()
        return self.etags[key]

    def delete(self, key, etag):
        assert self.etags[key] == etag
        del self.data[key]
        del self.etags[key]


@pytest.fixture
def objects():
    return FakeObjects()


@pytest.fixture
def store(objects):
    return BlobReportStore(objects)


@pytest.fixture
def live_report():
    report = FixtureReportStore().get(fixture_report_id("benign-1")).model_copy(deep=True)
    report.bundle.report_id = "0x" + "af" * 32
    report.bundle.provenance.collection = "live"
    report.bundle.provenance.fixture_id = None
    report.bundle.provenance.analyzer = "deterministic"
    for item in report.bundle.evidence:
        item.mode = "live"
    report.merkle = seal_bundle(report.bundle)
    report.chain_receipt = ChainReceipt(tx_hash=None, block_number=None, contract_address=None, network="sealed-not-anchored", mode="unanchored")
    return report


def settings(**kw):
    defaults = dict(runtime_mode="serverless", chain_mode="demo_fixture", report_storage="vercel_blob", live_checks=True,
        scan_api_secret="s" * 32, scan_allowed_hosts=("example.com",), openai_key="", openai_model="")
    return Settings(**(defaults | kw))


def test_durable_round_trip_new_instance_and_immutable_reference(store, objects, live_report):
    store.save(live_report)
    fresh = BlobReportStore(objects)
    report_id = live_report.bundle.report_id
    assert fresh.get(report_id) == live_report
    assert fresh.reference(report_id).root == live_report.merkle.root
    store.save(live_report)  # identical retries are idempotent
    changed = live_report.model_copy(deep=True)
    from app.models import RiskClass
    changed.bundle.risk = RiskClass.HIGH_RISK
    changed.merkle = seal_bundle(changed.bundle)
    with pytest.raises(StorageUnavailableError):
        store.save(changed)
    assert fresh.get(report_id) == live_report
    assert fresh.get(fixture_report_id("benign-1")) is not None
    assert fresh.get("0x" + "de" * 32) is None
    with pytest.raises(ValueError):
        fresh.get("../../secret")
    objects.down = True
    assert fresh.get(fixture_report_id("benign-1")) is not None
    with pytest.raises(StorageUnavailableError):
        fresh.get(report_id)
    with pytest.raises(StorageUnavailableError):
        fresh.save(live_report)


def test_missing_independent_reference_never_supported(store, objects, live_report):
    store.save(live_report)
    del objects.data[f"references/{live_report.bundle.report_id}.json"]
    with pytest.raises(StorageUnavailableError):
        ProductionVerifier(store).verify_bundle(live_report.bundle.report_id, live_report.bundle)


def test_sdk_always_private_bounded_and_conditional():
    from vercel.blob.errors import BlobNotFoundError, BlobAccessError, BlobError
    sdk = MagicMock()
    download = MagicMock()
    download.metadata.size = 3
    download.__iter__.return_value = iter([b"{}"])
    sdk.stream_blob.return_value.__enter__.return_value = download
    sdk.put_blob.return_value.etag = "etag"
    objects = PrivateBlobObjects(sdk)
    assert objects.get("reports/id.json") == b"{}"
    sdk.stream_blob.assert_called_with("veridict/v1/reports/id.json", access="private")
    assert objects.create("x", b"{}") == "etag"
    assert sdk.put_blob.call_args.kwargs["access"] == "private"
    assert sdk.put_blob.call_args.kwargs["allow_overwrite"] is False
    objects.delete("x", "etag")
    sdk.delete_blob.assert_called_with("veridict/v1/x", if_match="etag")
    sdk.stream_blob.side_effect = BlobNotFoundError()
    assert objects.get("missing") is None
    sdk.stream_blob.side_effect = BlobAccessError()
    assert not objects.available()
    with pytest.raises(StorageUnavailableError):
        objects.get("secret")
    sdk.put_blob.side_effect = BlobError("exists", status_code=409)
    with pytest.raises(ObjectExistsError):
        objects.create("x", b"{}")
    sdk.put_blob.side_effect = BlobAccessError()
    with pytest.raises(StorageUnavailableError):
        objects.create("x", b"{}")


def test_global_quotas_and_leases_survive_new_instances(objects):
    DurableControls(objects).consume("unit", 1)
    with pytest.raises(QuotaExceededError):
        DurableControls(objects).consume("unit", 1)
    with DurableControls(objects).lease("scanner"):
        with pytest.raises(QuotaExceededError):
            with DurableControls(objects).lease("scanner"):
                pytest.fail("overlapping lease")
    with DurableControls(objects).lease("scanner"):
        assert objects.get("controls/leases/scanner.json") is not None


def test_scan_gates_no_unsafe_outbound_and_fixture_fallback(store, objects):
    with TestClient(create_app(settings(), store=store)) as client:
        health = client.get("/health").json()
        assert health["live_scanning_enabled"] and not health["chain_connected"]
        assert health["report_storage"] == "vercel_blob"
        assert client.post("/api/investigate", json={"url": "https://example.com"}).status_code == 401
        for url in ["https://127.0.0.1", "http://example.com", "https://example.com:8443", "https://user:pass@example.com", "https://unapproved.example"]:
            response = client.post("/api/investigate", json={"url": url}, headers={"x-veridict-scan-secret": "s" * 32})
            assert response.status_code == 422
            assert "user:pass" not in response.text
        assert client.post(f"/api/reports/{fixture_report_id('benign-1')}/anchor").status_code == 401
        objects.down = True
        health = client.get("/health").json()
        assert not health["live_scanning_enabled"] and health["report_storage"] == "unavailable"
        fixture = client.get("/api/fixtures").json()[0]
        assert client.post("/api/investigate", json=fixture["input"]).status_code == 200


def test_live_collection_seal_save_reload_tamper_no_automatic_signer(store, objects, monkeypatch):
    from app.models import RedirectEvidence, RedirectData, TLSEvidence, TLSData, ThreatEvidence, ThreatData
    import app.pipeline as pipeline
    observed = []
    async def redirects(url, allowed_hosts=None):
        observed.append(url)
        return RedirectEvidence(id="redir:1", status="COMPLETE", mode="live", data=RedirectData(chain=[url]))
    async def tls(host, port):
        return TLSEvidence(id="tls:1", status="COMPLETE", mode="live", data=TLSData(trusted=True, hostname_ok=True, expired=False, cert_sha256="a" * 64))
    async def threat(url, config):
        return ThreatEvidence(id="ti:1", status="TIMEOUT", mode="live", data=ThreatData(provider="openphish", matched=None, queried_at="2026-11-11T00:00:00Z"))
    monkeypatch.setattr(pipeline, "inspect_redirects", redirects)
    monkeypatch.setattr(pipeline, "inspect_tls", tls)
    monkeypatch.setattr(pipeline, "lookup_openphish", threat)
    headers = {"x-veridict-scan-secret": "s" * 32, "x-veridict-client": "test"}
    with TestClient(create_app(settings(), store=store)) as client:
        response = client.post("/api/investigate", json={"url": "https://example.com/?token=CANARY_SECRET", "message": "Action Required: Maintenance"}, headers=headers)
        assert response.status_code == 200, response.text
        report = response.json()
        report_id = report["bundle"]["report_id"]
        assert report["bundle"]["risk"] == "INCONCLUSIVE"
        assert report["bundle"]["provenance"]["analyzer"] == "deterministic"
        assert report["chain_receipt"]["mode"] == "unanchored" and report["chain_receipt"]["tx_hash"] is None
        assert report["verification"]["public_chain_status"] == "NOT_CONFIGURED"
        assert all("CANARY_SECRET" not in u for u in observed)
        assert b"CANARY_SECRET" not in b"".join(objects.data.values())
    with TestClient(create_app(settings(), store=BlobReportStore(objects))) as cold:
        fetched = cold.get(f"/api/reports/{report_id}")
        assert fetched.status_code == 200 and fetched.json() == report
        for mutation, expected in [("tls_cert", "TAMPERED"), ("drop_threat_intel", "NOT_SUPPORTED"), ("alter_redirect", "TAMPERED"), ("unground_ai_claim", "NOT_SUPPORTED")]:
            result = cold.post(f"/api/reports/{report_id}/tamper-demo", json={"mutation": mutation})
            assert result.status_code == 200, result.text
            assert result.json()["verification"]["status"] == expected
            assert cold.get(f"/api/reports/{report_id}").json() == report
        assert cold.post(f"/api/reports/{report_id}/verify", json={}).json()["status"] == "SUPPORTED"


def sepolia_mock(root=None, schema=SCHEMA_HASH_HEX, timestamp=1):
    config = settings(chain_mode="public_chain", rpc_url="https://rpc.example", chain_id=11155111, contract_address="0x" + "12" * 20)
    w3 = MagicMock()
    w3.eth.chain_id = 11155111
    w3.eth.get_code.return_value = b"\x60\x01"
    contract = w3.eth.contract.return_value
    contract.functions.reports.return_value.call.return_value = (bytes.fromhex((root or "0x" + "aa" * 32)[2:]), bytes.fromhex(schema[2:]), timestamp)
    return SepoliaRegistry(config, w3), w3, config


def test_public_read_only_chain_schema_root_missing_rpc_and_code(store, live_report):
    store.save(live_report)
    report_id = live_report.bundle.report_id
    chain, w3, config = sepolia_mock(live_report.merkle.root)
    assert not config.chain_private_key
    verifier = ProductionVerifier(store, chain)
    checked = verifier.verify_bundle(report_id, live_report.bundle)
    assert checked.public_chain_status == "VERIFIED" and checked.status == "SUPPORTED"
    candidate = live_report.bundle.model_copy(deep=True)
    candidate.evidence[0].data.obfuscated = True
    tampered = verifier.verify_bundle(report_id, candidate)
    assert tampered.status == "TAMPERED" and tampered.public_chain_status == "MISMATCH"
    w3.eth.contract.return_value.functions.reports.return_value.call.return_value = (bytes(32), bytes(32), 0)
    assert verifier.verify_bundle(report_id, live_report.bundle).public_chain_status == "NOT_ANCHORED"
    w3.eth.chain_id = 1
    assert verifier.verify_bundle(report_id, live_report.bundle).public_chain_status == "UNAVAILABLE"
    w3.eth.chain_id = 11155111
    w3.eth.get_code.return_value = b""
    assert verifier.verify_bundle(report_id, live_report.bundle).public_chain_status == "UNAVAILABLE"
    w3.eth.get_code.return_value = b"\x60"
    w3.eth.contract.return_value.functions.reports.return_value.call.return_value = (bytes.fromhex(live_report.merkle.root[2:]), bytes(32), 1)
    assert verifier.verify_bundle(report_id, live_report.bundle).public_chain_status == "MISMATCH"


def test_signer_disabled_and_ambiguous_transaction_never_resigned(store, objects, live_report):
    store.save(live_report)
    report_id = live_report.bundle.report_id
    chain, w3, config = sepolia_mock(timestamp=0)
    service = AnchorService(config, store, chain, ProductionVerifier(store, chain))
    with pytest.raises(AnchorUnavailableError):
        service.anchor(report_id)
    service.settings = replace(config, anchor_enabled=True, anchor_api_secret="a" * 32, chain_private_key="test-only-placeholder")
    prepared = {"tx_hash": "0x" + "34" * 32, "raw": "0xdeadbeef", "contract_address": chain.address, "chain_id": 11155111, "root": live_report.merkle.root, "lock_etag": "unused"}
    store.put_once(f"signing/prepared/{report_id}.json", prepared)
    w3.eth.get_transaction_receipt.side_effect = TransactionNotFound("not mined")
    w3.eth.send_raw_transaction.side_effect = TimeoutError()
    assert service.anchor(report_id).status == "PENDING"
    assert service.anchor(report_id).status == "PENDING"
    w3.eth.account.sign_transaction.assert_not_called()
    assert w3.eth.send_raw_transaction.call_args.args[0] == bytes.fromhex("deadbeef")


def test_signer_existing_conflict_stops_before_transaction(store, live_report):
    store.save(live_report)
    chain, w3, config = sepolia_mock("0x" + "33" * 32)
    config = replace(config, anchor_enabled=True, anchor_api_secret="a" * 32, chain_private_key="placeholder")
    with pytest.raises(ValueError):
        AnchorService(config, store, chain, ProductionVerifier(store, chain)).anchor(live_report.bundle.report_id)
    w3.eth.send_raw_transaction.assert_not_called()


def test_signing_is_budgeted_persisted_before_send_and_idempotent(store, objects, live_report):
    from eth_account import Account
    from web3 import Web3
    store.save(live_report)
    report_id = live_report.bundle.report_id
    chain, w3, config = sepolia_mock(timestamp=0)
    account = Account.create()  # Ephemeral test-only key, never logged or exported.
    config = replace(config, anchor_enabled=True, anchor_api_secret="a" * 32, chain_private_key=account.key.hex())
    w3.eth.account = Account
    w3.to_wei = Web3.to_wei
    w3.eth.gas_price = 1_000_000_000
    w3.eth.get_balance.return_value = 10 ** 18
    w3.eth.get_transaction_count.return_value = 0
    function = w3.eth.contract.return_value.functions.register.return_value
    function.estimate_gas.return_value = 80000
    function.build_transaction.side_effect = lambda tx: {**tx, "to": chain.address, "value": 0, "data": "0x"}
    state = {"registered": False, "sent": 0}
    def read_optional(rid):
        return Anchor(live_report.merkle.root, SCHEMA_HASH_HEX, 1) if state["registered"] else None
    chain.read_optional = read_optional
    chain.status = lambda rid, root, db: AnchorResponse(report_id=rid, status="VERIFIED" if state["registered"] else "NOT_ANCHORED", contract_address=chain.address)
    def send(raw):
        saved = json.loads(objects.get(f"signing/prepared/{report_id}.json"))
        assert raw.hex() == saved["raw"][2:]
        assert objects.get(f"signing/intents/{report_id}.json") is not None
        state["registered"], state["sent"] = True, state["sent"] + 1
        return Web3.keccak(raw)
    def receipt(tx):
        if not state["registered"]:
            raise TransactionNotFound("not mined")
        return {"status": 1, "blockNumber": 42}
    w3.eth.get_transaction_receipt.side_effect = receipt
    w3.eth.send_raw_transaction.side_effect = send
    w3.eth.wait_for_transaction_receipt.side_effect = lambda tx, **kw: receipt(tx)
    service = AnchorService(config, store, chain, ProductionVerifier(store, chain))
    assert service.anchor(report_id).status == "VERIFIED"
    assert service.anchor(report_id).status == "VERIFIED"
    assert state["sent"] == 1
    assert objects.get("controls/leases/sepolia-signer.json") is None
    stored = json.loads(objects.get(f"anchors/{report_id}.json"))
    assert stored["block_number"] == 42 and stored["mode"] == "evm"
    assert account.key.hex().encode() not in b"".join(objects.data.values())


def test_signer_fee_cap_and_quota_fail_closed(store, objects, live_report):
    from web3 import Web3
    store.save(live_report)
    chain, w3, config = sepolia_mock(timestamp=0)
    config = replace(config, anchor_enabled=True, anchor_api_secret="a" * 32, chain_private_key="test-only-placeholder")
    w3.to_wei = Web3.to_wei
    w3.eth.gas_price = 100_000_000_000
    service = AnchorService(config, store, chain, ProductionVerifier(store, chain))
    with pytest.raises(AnchorUnavailableError):
        service.anchor(live_report.bundle.report_id)
    w3.eth.send_raw_transaction.assert_not_called()
    w3.eth.account.sign_transaction.assert_not_called()
    assert objects.get("controls/leases/sepolia-signer.json") is None
    # An incomplete signing intent must not be silently retried with a new nonce.
    with pytest.raises(AnchorUnavailableError):
        service.anchor(live_report.bundle.report_id)


async def test_rollout_redirect_stops_before_unapproved_connection(monkeypatch):
    from app.security import redirects
    called = []
    monkeypatch.setattr(redirects, "validate_public_destination", lambda h: ["93.184.216.34"])
    async def fetch(url, host, addresses):
        called.append(host)
        return 302, "https://unapproved.example/"
    monkeypatch.setattr(redirects, "fetch_location", fetch)
    evidence = await redirects.inspect_redirects("https://example.com", allowed_hosts=("example.com",))
    assert called == ["example.com"] and evidence.status == "INCOMPLETE"


async def test_serverless_openphish_cache_is_ephemeral_and_failure_unknown(monkeypatch, tmp_path):
    import time
    from app.intel import openphish
    monkeypatch.setattr(openphish, "_warm_feed", (time.time(), {"https://listed.example/"}))
    config = settings(openphish_cache_path=str(tmp_path / "must-not-exist"))
    result = await openphish.lookup_openphish("https://listed.example/", config)
    assert result.status == "COMPLETE" and result.data.matched is True
    assert not (tmp_path / "must-not-exist").exists()
    monkeypatch.setattr(openphish, "_warm_feed", (0, set()))
    def unavailable(host):
        raise TimeoutError()
    monkeypatch.setattr(openphish, "validate_public_destination", unavailable)
    result = await openphish.lookup_openphish("https://ordinary.example/", config)
    assert result.status == "TIMEOUT" and result.data.matched is None
