"""Optional Safe Browsing v5 URL adapter. Never sends unredacted URLs."""
import asyncio
import hashlib
import re
import time
from datetime import datetime, timezone
import httpx

from app.models import ThreatData, ThreatEvidence
from app.security.redact import redact_url

# Cache both hits and misses for the provider-specified duration; never retain raw URLs.
CACHE: dict[str, tuple[float, ThreatEvidence]] = {}


async def lookup_safebrowsing(url: str, key: str) -> ThreatEvidence:
    result = ThreatEvidence(id="ti:2", status="UNCONFIGURED", mode="live", data=ThreatData(provider="google_safe_browsing", queried_at=datetime.now(timezone.utc).isoformat()))
    if not key:
        return result
    safe_url = redact_url(url)
    cache_key = hashlib.sha256(safe_url.encode()).hexdigest()
    cached = CACHE.get(cache_key)
    if cached and cached[0] > time.monotonic():
        return cached[1].model_copy(deep=True)
    try:
        async with httpx.AsyncClient(timeout=3, trust_env=False, follow_redirects=False) as client:
            async with asyncio.timeout(3):
                response = await client.get("https://safebrowsing.googleapis.com/v5/urls:search", params={"urls": safe_url}, headers={"X-Goog-Api-Key": key})
                response.raise_for_status()
                body = response.json()
                if not isinstance(body, dict) or not isinstance(body.get("threats", []), list):
                    raise ValueError("Invalid threat response")
                duration = body.get("cacheDuration", "")
                if not isinstance(duration, str) or not re.fullmatch(r"\d+(?:\.\d{1,9})?s", duration):
                    raise ValueError("Missing or invalid provider cache duration")
        result.status = "COMPLETE"
        result.data.matched = bool(body.get("threats"))
        if len(CACHE) >= 512:
            CACHE.pop(next(iter(CACHE)))
        CACHE[cache_key] = (time.monotonic() + min(float(duration[:-1]), 86400), result.model_copy(deep=True))
    except (TimeoutError, httpx.TimeoutException):
        result.status = "TIMEOUT"
    except Exception:
        result.status = "FAILED"
    return result
