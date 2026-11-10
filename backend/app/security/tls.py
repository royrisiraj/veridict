"""Pinned X.509 inspection. Unverified reconnects retrieve certificates only."""
import asyncio
import hashlib
import ipaddress
import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.x509.oid import ExtensionOID
from app.models import TLSData, TLSEvidence
from app.security.ssrf import SSRFBlockedError, validate_ip, validate_public_destination
from app.security.redact import redact_text


def certificate_matches(cert: x509.Certificate, host: str) -> bool:
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
    except x509.ExtensionNotFound:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        names = san.get_values_for_type(x509.DNSName)
        for name in names:
            name = name.lower().rstrip(".")
            if name == host.lower().rstrip("."):
                return True
            if name.startswith("*.") and host.count(".") == name.count(".") and host.endswith(name[1:]):
                return True
        return False
    return address in san.get_values_for_type(x509.IPAddress)


def read_certificate(host: str, port: int, ip: str, verify: bool) -> bytes:
    # Numeric socket.connect prevents a second hostname lookup.
    address = ipaddress.ip_address(ip)
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with socket.socket(socket.AF_INET6 if address.version == 6 else socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.settimeout(3.0)
        raw.connect((ip, port))
        if validate_ip(raw.getpeername()[0]) != validate_ip(ip):
            raise SSRFBlockedError("TLS peer did not match pinned destination")
        with context.wrap_socket(raw, server_hostname=host) as secured:
            return secured.getpeercert(binary_form=True)


def _inspect_tls(host: str, port: int) -> TLSEvidence:
    data = TLSData()
    try:
        addresses = validate_public_destination(host)
        last_error = None
        for address in addresses:
            try:
                try:
                    der = read_certificate(host, port, address, True)
                    trusted = True
                except ssl.SSLCertVerificationError:
                    der = read_certificate(host, port, address, False)
                    trusted = False
                cert = x509.load_der_x509_certificate(der)
                now = datetime.now(timezone.utc)
                data = TLSData(hostname_ok=certificate_matches(cert, host),
                    expired=now > cert.not_valid_after_utc, self_signed=cert.issuer == cert.subject,
                    trusted=trusted, issuer=redact_text(cert.issuer.rfc4514_string()), cert_sha256=hashlib.sha256(der).hexdigest(),
                    not_before=cert.not_valid_before_utc.isoformat(), not_after=cert.not_valid_after_utc.isoformat())
                return TLSEvidence(id="tls:1", status="COMPLETE", mode="live", data=data)
            except (TimeoutError, OSError) as exc:
                last_error = exc
        raise last_error or OSError("No certificate")
    except TimeoutError:
        status = "TIMEOUT"
    except Exception:
        status = "FAILED"
    return TLSEvidence(id="tls:1", status=status, mode="live", data=data)


async def inspect_tls(host: str, port: int = 443) -> TLSEvidence:
    return await asyncio.to_thread(_inspect_tls, host, port)
