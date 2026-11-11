"""Validate every DNS answer and pin all socket connections to validated IPs."""
import ipaddress
import socket
from urllib.parse import urlsplit

import dns.resolver
import httpcore
import httpx
from httpcore._backends.anyio import AnyIOBackend


class SSRFBlockedError(ValueError):
    """Destination is not public; the exception never contains submitted input."""


def validate_ip(value: str) -> str:
    try:
        if "%" in value:
            raise ValueError("Scoped address")
        address = ipaddress.ip_address(value)
        nested = getattr(address, "ipv4_mapped", None) or getattr(address, "sixtofour", None)
        if nested:
            validate_ip(str(nested))
        if not address.is_global or address.is_reserved or address.is_multicast or getattr(address, "teredo", None):
            raise ValueError("Non-public address")
        return str(address)
    except ValueError:
        raise SSRFBlockedError("Non-public destination blocked") from None


def resolve_addresses(host: str) -> list[str]:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    addresses = []
    for record_type in ("A", "AAAA"):
        try:
            addresses.extend(str(a) for a in resolver.resolve(host, record_type))
        except dns.resolver.NoAnswer:
            continue
    return addresses


def validate_public_destination(host: str) -> list[str]:
    # Host-only API; callers validate the URL scheme separately.
    if not host or any(c in host for c in "/\\@%"):
        raise SSRFBlockedError("Invalid destination")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        addresses = resolve_addresses(host)
    else:
        addresses = [str(address)]
    if not addresses:
        raise OSError("Destination did not resolve")
    return sorted(set(validate_ip(ip) for ip in addresses))


class PinnedBackend(httpcore.AsyncNetworkBackend):
    def __init__(self, hostname: str, addresses: list[str]):
        self.hostname = hostname
        self.addresses = [validate_ip(ip) for ip in addresses]
        self.backend = AnyIOBackend()

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host != self.hostname:
            raise SSRFBlockedError("Unvalidated hostname blocked")
        last_error = None
        for ip in self.addresses:
            try:
                stream = await self.backend.connect_tcp(ip, port, timeout, local_address, socket_options)
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last_error = exc
                continue
            peer = stream.get_extra_info("server_addr")
            try:
                valid_peer = peer and validate_ip(peer[0]) in self.addresses
            except SSRFBlockedError:
                await stream.aclose()
                raise
            if not valid_peer:
                await stream.aclose()
                raise SSRFBlockedError("Connected peer did not match pinned destination")
            return stream
        raise httpcore.ConnectError("Pinned destination unavailable") from last_error

    async def connect_unix_socket(self, *args, **kwargs):
        raise SSRFBlockedError("Unix sockets are prohibited")

    async def sleep(self, seconds):
        await self.backend.sleep(seconds)


class ResponseStream(httpx.AsyncByteStream):
    def __init__(self, stream):
        self.stream = stream

    async def __aiter__(self):
        async for chunk in self.stream:
            yield chunk

    async def aclose(self):
        await self.stream.aclose()


class PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, hostname: str, addresses: list[str]):
        self.pool = httpcore.AsyncConnectionPool(network_backend=PinnedBackend(hostname, addresses), max_connections=1, retries=0)

    async def handle_async_request(self, request):
        response = await self.pool.handle_async_request(httpcore.Request(
            method=request.method, url=httpcore.URL(scheme=request.url.raw_scheme, host=request.url.raw_host,
                port=request.url.port, target=request.url.raw_path), headers=request.headers.raw,
            content=request.stream, extensions=request.extensions))
        return httpx.Response(response.status, headers=response.headers, stream=ResponseStream(response.stream), extensions=response.extensions)

    async def aclose(self):
        await self.pool.aclose()


def destination(url: str) -> tuple[str, int]:
    parts = urlsplit(url)
    if parts.scheme not in {"http", "https"} or not parts.hostname or parts.username or parts.password:
        raise SSRFBlockedError("Only credential-free HTTP(S) destinations are allowed")
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if port not in {80, 443}:
        raise SSRFBlockedError("Unsafe destination port blocked")
    return parts.hostname, port
