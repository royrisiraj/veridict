import json
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from web3 import Web3
from app.canonical import SCHEMA_HASH_HEX
from app.config import Settings
from app.models import ChainReceipt


class AnchorUnavailableError(RuntimeError):
    """No trusted anchor can currently be read."""


@dataclass(frozen=True)
class Anchor:
    root: str
    schema_hash: str
    timestamp: int


class MemoryRegistry:
    mode = "fixture"
    connected = False
    address = ""

    def __init__(self):
        self.records: dict[str, Anchor] = {}
        self.lock = threading.Lock()

    def register(self, report_id: str, root: str) -> ChainReceipt:
        with self.lock:
            if report_id in self.records or int(root, 16) == 0:
                raise ValueError("Duplicate ID or zero root")
            self.records[report_id] = Anchor(root, SCHEMA_HASH_HEX, int(time.time()))
        return ChainReceipt(tx_hash=None, block_number=None, contract_address=None, network="fixture-memory", mode="fixture")

    def read(self, report_id: str) -> Anchor:
        if report_id not in self.records:
            raise AnchorUnavailableError("Simulated anchor is unavailable in this process")
        return self.records[report_id]


ABI = [
    {"type": "function", "name": "register", "stateMutability": "nonpayable", "inputs": [{"name": n, "type": "bytes32"} for n in ["id", "root", "schemaHash"]], "outputs": []},
    {"type": "function", "name": "reports", "stateMutability": "view", "inputs": [{"name": "id", "type": "bytes32"}], "outputs": [{"name": "root", "type": "bytes32"}, {"name": "schemaHash", "type": "bytes32"}, {"name": "timestamp", "type": "uint64"}]},
]


class EVMRegistry:
    mode = "evm"

    def __init__(self, settings: Settings):
        self.web3 = Web3(Web3.HTTPProvider(settings.rpc_url, request_kwargs={"timeout": 3}))
        address = settings.contract_address
        if not address and Path(settings.deployment_path).exists():
            address = json.loads(Path(settings.deployment_path).read_text())["contract_address"]
        if not self.web3.is_connected() or not address:
            raise AnchorUnavailableError("Configured EVM registry unavailable")
        self.address = Web3.to_checksum_address(address)
        if not self.web3.eth.get_code(self.address):
            raise AnchorUnavailableError("Registry bytecode unavailable")
        self.contract = self.web3.eth.contract(address=self.address, abi=ABI)
        self.chain_id = self.web3.eth.chain_id
        if settings.chain_id is not None and self.chain_id != settings.chain_id:
            raise AnchorUnavailableError("Configured chain ID does not match RPC")
        self.key = settings.chain_private_key
        if not self.key and self.chain_id != 31337:
            raise AnchorUnavailableError("A signer is required outside local Hardhat")
        self.sender = self.web3.eth.account.from_key(self.key).address if self.key else self.web3.eth.accounts[0]
        self.lock = threading.Lock()
        self.health_connected = True

    @property
    def connected(self):
        try:
            return self.web3.is_connected() and bool(self.web3.eth.get_code(self.address))
        except Exception:
            return False

    def register(self, report_id: str, root: str) -> ChainReceipt:
        try:
            with self.lock:
                function = self.contract.functions.register(bytes.fromhex(report_id[2:]), bytes.fromhex(root[2:]), bytes.fromhex(SCHEMA_HASH_HEX[2:]))
                if self.key:
                    transaction = function.build_transaction({"from": self.sender, "nonce": self.web3.eth.get_transaction_count(self.sender), "chainId": self.chain_id})
                    signed = self.web3.eth.account.sign_transaction(transaction, self.key)
                    tx = self.web3.eth.send_raw_transaction(signed.raw_transaction)
                else:
                    tx = function.transact({"from": self.sender})
                receipt = self.web3.eth.wait_for_transaction_receipt(tx, timeout=30)
            if receipt.status != 1:
                raise AnchorUnavailableError("Registry transaction reverted")
            return ChainReceipt(tx_hash="0x" + bytes(tx).hex(), block_number=receipt.blockNumber,
                contract_address=self.address, network=f"evm:{self.chain_id}", mode="evm")
        except Exception:
            raise AnchorUnavailableError("Registration failed; no report was saved") from None

    def read(self, report_id: str) -> Anchor:
        try:
            root, schema, timestamp = self.contract.functions.reports(bytes.fromhex(report_id[2:])).call()
            if not timestamp:
                raise AnchorUnavailableError("Anchor is missing")
            self.health_connected = True
            return Anchor("0x" + bytes(root).hex(), "0x" + bytes(schema).hex(), int(timestamp))
        except Exception:
            self.health_connected = False
            raise AnchorUnavailableError("EVM anchor unavailable") from None


def create_registry(settings: Settings):
    if settings.chain_mode == "unavailable":
        from app.deployment import UnavailableRegistry
        return UnavailableRegistry()
    if settings.chain_mode == "demo_fixture":
        from app.deployment import FixtureRegistry
        return FixtureRegistry()
    if settings.chain_mode == "fixture":
        return MemoryRegistry()
    if settings.chain_mode == "public_chain":
        parts = urlsplit(settings.rpc_url)
        if parts.scheme != "https" or parts.hostname in {None, "localhost", "127.0.0.1", "::1"} or not settings.chain_id or settings.chain_id == 31337 or not settings.contract_address or not settings.chain_private_key:
            raise AnchorUnavailableError("Public chain requires HTTPS RPC, expected CHAIN_ID, deployed contract and server-side signer")
    try:
        return EVMRegistry(settings)
    except Exception:
        if settings.chain_mode in {"evm", "public_chain"}:
            raise AnchorUnavailableError("Explicit EVM mode requires a deployed reachable registry") from None
        return MemoryRegistry()
