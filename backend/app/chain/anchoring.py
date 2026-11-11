"""Opt-in operator signing with durable intents, nonce serialization and budgets.

Ambiguous broadcasts retain the signer lease. Recovery checks the same signed
transaction; a retry never signs a replacement or fabricates a receipt.
"""
import json
from datetime import datetime, timezone

from web3.exceptions import TransactionNotFound, TimeExhausted
from app.canonical import canonical_json, SCHEMA_HASH_HEX
from app.chain.registry import AnchorUnavailableError
from app.models import AnchorResponse, ChainReceipt
from app.sealing import seal_bundle
from app.storage import DurableControls, ObjectExistsError, QuotaExceededError, StorageUnavailableError


class AnchorService:
    def __init__(self, settings, store, chain, verifier):
        self.settings, self.store, self.chain, self.verifier = settings, store, chain, verifier

    def enabled(self):
        return bool(self.settings.anchor_enabled and len(self.settings.anchor_api_secret) >= 32
            and self.settings.chain_private_key and self.chain and hasattr(self.store, "objects"))

    def anchor(self, report_id):
        if not self.enabled():
            raise AnchorUnavailableError("Protected registration is not configured")
        report = self.store.get(report_id)
        if report is None:
            raise LookupError("Report not found")
        if seal_bundle(report.bundle) != report.merkle:
            raise ValueError("Passport seal differs")
        checked = self.verifier.verify_bundle(report_id, report.bundle)
        if checked.status != "SUPPORTED":
            raise ValueError("Passport cannot be anchored")
        self.chain.check()
        existing = self.chain.read_optional(report_id)
        if existing:
            if existing.root != report.merkle.root or existing.schema_hash != SCHEMA_HASH_HEX:
                raise ValueError("Registry report ID conflict")
            # Finalize a previously broadcast transaction after a timeout/crash.
            prepared = self.store.objects.get(f"signing/prepared/{report_id}.json")
            if prepared:
                return self._finish(report, json.loads(prepared), wait=False)
            return self.chain.status(report_id, report.merkle.root, self.store)
        prepared = self.store.objects.get(f"signing/prepared/{report_id}.json")
        if prepared:
            return self._finish(report, json.loads(prepared), wait=True)

        objects, w3, settings = self.store.objects, self.chain.web3, self.settings
        lock_key = "controls/leases/sepolia-signer.json"
        try:
            lock_etag = objects.create(lock_key, canonical_json({"report_id": report_id}))
        except ObjectExistsError:
            raise QuotaExceededError("Signer already active or awaiting recovery") from None
        signed_persisted = False
        try:
            # A separate immutable intent makes crashes before signing fail closed.
            try:
                objects.create(f"signing/intents/{report_id}.json", canonical_json({"root": report.merkle.root}))
            except ObjectExistsError:
                raise AnchorUnavailableError("Previous signing intent requires operator recovery") from None
            DurableControls(objects).consume("anchor/" + datetime.now(timezone.utc).strftime("%Y%m%d"), settings.anchor_daily_limit)
            account = w3.eth.account.from_key(settings.chain_private_key)
            fee_cap = w3.to_wei(settings.anchor_max_fee_gwei, "gwei")
            gas_price = w3.eth.gas_price
            if gas_price > fee_cap:
                raise AnchorUnavailableError("Current gas price exceeds operator cap")
            function = self.chain.contract.functions.register(bytes.fromhex(report_id[2:]), bytes.fromhex(report.merkle.root[2:]), bytes.fromhex(SCHEMA_HASH_HEX[2:]))
            estimated = function.estimate_gas({"from": account.address})
            gas = min(settings.anchor_max_gas, (estimated * 120 + 99) // 100)
            if estimated > gas or w3.eth.get_balance(account.address) < gas * gas_price:
                raise AnchorUnavailableError("Gas budget or testnet balance insufficient")
            transaction = function.build_transaction({"from": account.address, "nonce": w3.eth.get_transaction_count(account.address, "pending"),
                "chainId": 11155111, "gas": gas, "gasPrice": gas_price})
            signed = w3.eth.account.sign_transaction(transaction, settings.chain_private_key)
            prepared = {"tx_hash": "0x" + bytes(signed.hash).hex(), "raw": "0x" + bytes(signed.raw_transaction).hex(),
                "contract_address": self.chain.address, "chain_id": 11155111, "root": report.merkle.root, "lock_etag": lock_etag}
            self.store.put_once(f"signing/prepared/{report_id}.json", prepared)
            signed_persisted = True
            return self._finish(report, prepared, wait=True)
        finally:
            # Signed transactions may have escaped even if the RPC timed out.
            if not signed_persisted:
                objects.delete(lock_key, lock_etag)

    def _finish(self, report, prepared, wait):
        w3, report_id = self.chain.web3, report.bundle.report_id
        self.chain.check()
        if prepared["contract_address"] != self.chain.address or prepared["chain_id"] != 11155111 or prepared["root"] != report.merkle.root:
            raise AnchorUnavailableError("Prepared transaction source mismatch")
        tx_hash = prepared["tx_hash"]
        try:
            try:
                mined = w3.eth.get_transaction_receipt(tx_hash)
            except TransactionNotFound:
                if not wait:
                    return AnchorResponse(report_id=report_id, status="PENDING", contract_address=self.chain.address)
                try:
                    returned = w3.eth.send_raw_transaction(bytes.fromhex(prepared["raw"][2:]))
                    if "0x" + bytes(returned).hex() != tx_hash:
                        raise AnchorUnavailableError("Unexpected broadcast hash")
                except Exception:
                    # Already known, pending, and uncertain transport failures all
                    # reconcile the exact persisted hash, never another nonce.
                    return self._pending_or_mined(report, prepared)
                mined = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=12, poll_latency=1)
        except (TransactionNotFound, TimeExhausted, TimeoutError):
            return AnchorResponse(report_id=report_id, status="PENDING", contract_address=self.chain.address)
        except Exception:
            raise AnchorUnavailableError("Transaction status unavailable; lease retained") from None
        if mined["status"] != 1:
            raise AnchorUnavailableError("Registration reverted; inspect transaction before unlocking signer")
        registered = self.chain.read_optional(report_id)
        if not registered or registered.root != report.merkle.root or registered.schema_hash != SCHEMA_HASH_HEX:
            raise AnchorUnavailableError("Registry readback failed; lease retained")
        receipt = ChainReceipt(tx_hash=tx_hash, block_number=int(mined["blockNumber"]), contract_address=self.chain.address, network="evm:11155111", mode="evm")
        self.store.put_once(f"anchors/{report_id}.json", receipt.model_dump(mode="json"))
        # Only release our own lease; repeated finalization is safe.
        lock_key = "controls/leases/sepolia-signer.json"
        lock = self.store.objects.get(lock_key)
        if lock and json.loads(lock).get("report_id") == report_id:
            self.store.objects.delete(lock_key, prepared["lock_etag"])
        return self.chain.status(report_id, report.merkle.root, self.store)

    def _pending_or_mined(self, report, prepared):
        return self._finish(report, prepared, wait=False)
