"""Environment settings; offline collection is the safe, dependency-free default."""
import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Settings:
    database_path: str = field(default_factory=lambda: os.getenv("DATABASE_PATH", str(ROOT / "runtime/veridict.db")))
    live_checks: bool = field(default_factory=lambda: os.getenv("LIVE_CHECKS", "false").lower() == "true")
    chain_mode: str = field(default_factory=lambda: os.getenv("CHAIN_MODE", "auto"))
    rpc_url: str = field(default_factory=lambda: os.getenv("RPC_URL", "http://127.0.0.1:8545"))
    contract_address: str = field(default_factory=lambda: os.getenv("CONTRACT_ADDRESS", ""))
    deployment_path: str = field(default_factory=lambda: os.getenv("DEPLOYMENT_PATH", str(ROOT / "runtime/deployment.json")))
    chain_private_key: str = field(default_factory=lambda: os.getenv("CHAIN_PRIVATE_KEY", ""), repr=False)
    openphish_cache_path: str = field(default_factory=lambda: os.getenv("OPENPHISH_CACHE_PATH", str(ROOT / "runtime/openphish.txt")))
    openphish_cache_max_age: int = field(default_factory=lambda: int(os.getenv("OPENPHISH_CACHE_MAX_AGE", "86400")))
    safe_browsing_key: str = field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_KEY", ""), repr=False)
    openai_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""), repr=False)
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", ""))
    cors_origins: list[str] = field(default_factory=lambda: os.getenv("CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000").split(","))

    def __post_init__(self):
        if self.chain_mode not in {"auto", "evm", "fixture"}:
            raise ValueError("CHAIN_MODE must be auto, evm or fixture")
