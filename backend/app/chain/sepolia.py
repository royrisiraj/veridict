"""Read-only Sepolia access. No signer or local-chain fallback is required."""
from urllib.parse import urlsplit
from web3 import Web3

from app.canonical import SCHEMA_HASH_HEX
from app.chain.registry import ABI, Anchor, AnchorUnavailableError
from app.models import AnchorResponse, ChainReceipt
from app.storage import report_key, StorageUnavailableError

SEPOLIA_ID = 11155111


class SepoliaRegistry:
    def __init__(self, settings, web3=None):
        parts = urlsplit(settings.rpc_url)
        if settings.chain_id != SEPOLIA_ID or not settings.contract_address or parts.scheme != "https" or parts.hostname in {None, "localhost", "127.0.0.1", "::1"}:
            raise AnchorUnavailableError("Sepolia requires HTTPS RPC, CHAIN_ID 11155111 and deployed contract")
        self.web3 = web3 or Web3(Web3.HTTPProvider(settings.rpc_url, request_kwargs={"timeout": 3}))
        self.address = Web3.to_checksum_address(settings.contract_address)
        self.chain_id = SEPOLIA_ID
        self.contract = self.web3.eth.contract(address=self.address, abi=ABI)

    def check(self):
        try:
            if self.web3.eth.chain_id != SEPOLIA_ID or not self.web3.eth.get_code(self.address):
                raise ValueError("Wrong chain or missing code")
            # Exercise the deployed ABI as well as checking nonempty bytecode.
            self.contract.functions.reports(bytes(32)).call()
            return True
        except Exception:
            raise AnchorUnavailableError("Sepolia registry unavailable") from None

    def read_optional(self, report_id):
        report_key(report_id)
        self.check()
        try:
            root, schema, timestamp = self.contract.functions.reports(bytes.fromhex(report_id[2:])).call()
            return Anchor("0x" + bytes(root).hex(), "0x" + bytes(schema).hex(), int(timestamp)) if timestamp else None
        except Exception:
            raise AnchorUnavailableError("Sepolia record unavailable") from None

    def status(self, report_id, expected_root, store):
        try:
            anchor = self.read_optional(report_id)
        except AnchorUnavailableError:
            return AnchorResponse(report_id=report_id, status="UNAVAILABLE", contract_address=self.address)
        if anchor is None:
            return AnchorResponse(report_id=report_id, status="NOT_ANCHORED", contract_address=self.address)
        status = "VERIFIED" if anchor.root == expected_root and anchor.schema_hash == SCHEMA_HASH_HEX else "MISMATCH"
        receipt = None
        # Metadata is only displayed if its transaction can be independently read.
        if hasattr(store, "objects"):
            import json
            try:
                data = store.objects.get(f"anchors/{report_id}.json")
            except StorageUnavailableError:
                data = None  # Root was actually queried; transaction metadata is optional.
            if data:
                saved = ChainReceipt.model_validate(json.loads(data))
                if saved.contract_address == self.address and saved.network == f"evm:{SEPOLIA_ID}" and saved.tx_hash:
                    try:
                        tx = self.web3.eth.get_transaction(saved.tx_hash)
                        mined = self.web3.eth.get_transaction_receipt(saved.tx_hash)
                        function, values = self.contract.decode_function_input(tx["input"])
                        if mined["status"] == 1 and tx["to"] == self.address and function.fn_name == "register" and "0x" + bytes(values["id"]).hex() == report_id and "0x" + bytes(values["root"]).hex() == expected_root and "0x" + bytes(values["schemaHash"]).hex() == SCHEMA_HASH_HEX:
                            receipt = saved.model_copy(update={"block_number": int(mined["blockNumber"])})
                    except Exception:
                        return AnchorResponse(report_id=report_id, status="UNAVAILABLE", contract_address=self.address)
        return AnchorResponse(report_id=report_id, status=status, contract_address=self.address, receipt=receipt,
            explorer_url=f"https://sepolia.etherscan.io/tx/{receipt.tx_hash}" if receipt else None)
