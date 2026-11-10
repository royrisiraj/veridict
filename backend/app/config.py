"""Environment settings; offline collection is the safe, dependency-free default."""
import os
from dataclasses import dataclass, field
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[2]


def serverless_environment() -> bool:
    return os.getenv("VERCEL") == "1" or os.getenv("RUNTIME_MODE") == "serverless"


@dataclass(frozen=True)
class Settings:
    runtime_mode: str = field(default_factory=lambda: "serverless" if serverless_environment() else "native")
    database_path: str = field(default_factory=lambda: os.getenv("DATABASE_PATH", str(ROOT / "runtime/veridict.db")))
    live_checks: bool = field(default_factory=lambda: os.getenv("LIVE_CHECKS", "false").lower() == "true")
    chain_mode: str = field(default_factory=lambda: os.getenv("CHAIN_MODE", "auto"))
    rpc_url: str = field(default_factory=lambda: os.getenv("RPC_URL", "" if serverless_environment() else "http://127.0.0.1:8545"), repr=False)
    chain_id: int | None = field(default_factory=lambda: int(os.environ["CHAIN_ID"]) if os.getenv("CHAIN_ID") else None)
    contract_address: str = field(default_factory=lambda: os.getenv("CONTRACT_ADDRESS", ""))
    deployment_path: str = field(default_factory=lambda: os.getenv("DEPLOYMENT_PATH", str(ROOT / "runtime/deployment.json")))
    chain_private_key: str = field(default_factory=lambda: os.getenv("CHAIN_PRIVATE_KEY", ""), repr=False)
    openphish_cache_path: str = field(default_factory=lambda: os.getenv("OPENPHISH_CACHE_PATH", str(Path(tempfile.gettempdir()) / "veridict-openphish.txt") if serverless_environment() else str(ROOT / "runtime/openphish.txt")))
    openphish_cache_max_age: int = field(default_factory=lambda: int(os.getenv("OPENPHISH_CACHE_MAX_AGE", "86400")))
    safe_browsing_key: str = field(default_factory=lambda: os.getenv("GOOGLE_SAFE_BROWSING_KEY", ""), repr=False)
    openai_key: str = field(default_factory=lambda: os.getenv("OPENAI_API_KEY", ""), repr=False)
    openai_model: str = field(default_factory=lambda: os.getenv("OPENAI_MODEL", ""))
    cors_origins: list[str] = field(default_factory=lambda: [origin.strip() for origin in os.getenv("CORS_ORIGINS", "" if serverless_environment() else "http://localhost:3000,http://127.0.0.1:3000").split(",") if origin.strip()])

    def __post_init__(self):
        if self.runtime_mode not in {"native", "serverless"}:
            raise ValueError("RUNTIME_MODE must be native or serverless")
        object.__setattr__(self, "chain_mode", self.chain_mode.lower())
        if self.chain_mode not in {"auto", "evm", "fixture", "demo_fixture", "public_chain", "unavailable"}:
            raise ValueError("Invalid CHAIN_MODE")
