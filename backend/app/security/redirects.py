"""HEAD-only, bounded manual redirects through pinned connections."""
import asyncio
from urllib.parse import urljoin, urlsplit

import httpx
from app.models import RedirectData, RedirectEvidence
from app.security.redact import redact_url
from app.security.ssrf import PinnedTransport, SSRFBlockedError, destination, validate_public_destination


async def fetch_location(url: str, host: str, addresses: list[str]) -> tuple[int, str | None]:
    async with httpx.AsyncClient(transport=PinnedTransport(host, addresses), trust_env=False, follow_redirects=False, timeout=3.0) as client:
        async with asyncio.timeout(3.0):
            async with client.stream("HEAD", url, headers={"User-Agent": "VERIDICT/1 evidence-inspector"}) as response:
                location = response.headers.get("location")
                if location and len(location) > 4096:
                    raise ValueError("Redirect location exceeds limit")
                return response.status_code, location


async def inspect_redirects(url: str, max_hops: int = 4, allowed_hosts: tuple[str, ...] | None = None) -> RedirectEvidence:
    chain = [redact_url(url)]
    seen = set()
    current = url
    data = RedirectData(chain=chain)
    status = "COMPLETE"
    try:
        for hop in range(max_hops + 1):
            host, _ = destination(current)
            if allowed_hosts is not None and host.lower() not in allowed_hosts:
                raise ValueError("Destination outside controlled rollout")
            addresses = await asyncio.to_thread(validate_public_destination, host)
            if current in seen:
                data.loop_detected = True
                status = "FAILED"
                break
            seen.add(current)
            code, location = await fetch_location(current, host, addresses)
            if code not in {301, 302, 303, 307, 308} or not location:
                break
            next_url = urljoin(current, location)
            next_host, _ = destination(next_url)
            if allowed_hosts is not None and next_host.lower() not in allowed_hosts:
                status = "INCOMPLETE"
                break
            # Validate even the destination beyond the permitted redirect count.
            await asyncio.to_thread(validate_public_destination, next_host)
            if hop == max_hops:
                data.limit_reached = True
                status = "INCOMPLETE"
                break
            if next_host != host:
                data.cross_domain_hops += 1
                data.untrusted_destination = True
            chain.append(redact_url(next_url))
            current = next_url
    except SSRFBlockedError:
        data.ssrf_blocked = True
        status = "FAILED"
    except (TimeoutError, httpx.TimeoutException):
        status = "TIMEOUT"
    except Exception:
        status = "FAILED"
    data.chain = chain
    return RedirectEvidence(id="redir:1", status=status, mode="live", data=data)
