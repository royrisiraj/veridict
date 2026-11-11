import asyncio
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx
from app.config import Settings
from app.models import ThreatData, ThreatEvidence
from app.security.redact import redact_url
from app.security.ssrf import PinnedTransport, validate_public_destination

FEED_URL = "https://openphish.com/feed.txt"
_warm_feed: tuple[float, set[str]] = (0, set())


async def lookup_openphish(url: str, settings: Settings | None = None) -> ThreatEvidence:
    global _warm_feed
    settings = settings or Settings()
    cache = Path(settings.openphish_cache_path)
    queried = datetime.now(timezone.utc).isoformat()
    result = ThreatEvidence(id="ti:1", status="INCOMPLETE", mode="live", data=ThreatData(provider="openphish", queried_at=queried))
    try:
        hosted = settings.runtime_mode == "serverless"
        fresh = (bool(_warm_feed[1]) and time.time() - _warm_feed[0] <= settings.openphish_cache_max_age) if hosted else cache.exists() and time.time() - cache.stat().st_mtime <= settings.openphish_cache_max_age
        if not fresh:
            addresses = await asyncio.to_thread(validate_public_destination, "openphish.com")
            async with httpx.AsyncClient(transport=PinnedTransport("openphish.com", addresses), timeout=3, trust_env=False, follow_redirects=False) as client:
                async with asyncio.timeout(3):
                    async with client.stream("GET", FEED_URL) as response:
                        response.raise_for_status()
                        chunks = bytearray()
                        async for chunk in response.aiter_bytes():
                            chunks.extend(chunk)
                            if len(chunks) > 4_000_000:
                                raise ValueError("Feed exceeds limit")
            lines = [redact_url(line) for line in chunks.decode().splitlines() if line.startswith(("https://", "http://"))]
            if not lines:
                raise ValueError("Empty or invalid feed")
            if hosted:
                _warm_feed = (time.time(), set(lines))
            else:
                cache.parent.mkdir(parents=True, exist_ok=True)
                cache.write_text("\n".join(lines), encoding="utf-8")
        entries = _warm_feed[1] if hosted else {redact_url(line.strip()) for line in cache.read_text(encoding="utf-8").splitlines() if line.strip()}
        if not entries:
            raise ValueError("Empty cache")
        result.status = "COMPLETE"
        result.data.matched = redact_url(url) in entries
    except (TimeoutError, httpx.TimeoutException):
        result.status = "TIMEOUT"
    except Exception:
        result.status = "FAILED"
    return result
