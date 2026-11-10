"""HTTP URL normalization and conservative, deterministic protected-brand rules."""
import re
from difflib import SequenceMatcher
from urllib.parse import urlsplit, urlunsplit

import idna
from app.models import URLData
from app.security.redact import redact_url

PROTECTED = {"paypal": "paypal.com", "microsoft": "microsoft.com", "google": "google.com", "apple": "apple.com", "coinbase": "coinbase.com", "examplebank": "examplebank.com"}
CONFUSABLES = str.maketrans({"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ӏ": "l", "Ι": "l"})


def normalize_url(raw: str) -> URLData:
    if any(ord(c) < 32 or c == "\\" for c in raw):
        raise ValueError("Invalid URL characters")
    parsed = urlsplit(raw.strip())
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise ValueError("An absolute HTTP(S) URL is required")
    original = parsed.hostname.rstrip(".").lower()
    try:
        host = idna.encode(original, uts46=True).decode() if ":" not in original else original
        port = parsed.port
    except (ValueError, idna.IDNAError):
        raise ValueError("Invalid hostname or port") from None
    host_part = f"[{host}]" if ":" in host else host
    authority = host_part + (f":{port}" if port and port != (443 if parsed.scheme.lower() == "https" else 80) else "")
    normalized = urlunsplit((parsed.scheme.lower(), authority, parsed.path or "/", parsed.query, ""))
    unicode_host = idna.decode(host) if ":" not in host else host
    skeleton = unicode_host.translate(CONFUSABLES).replace("0", "o")
    target = None
    for brand, domain in PROTECTED.items():
        if host == domain or host.endswith("." + domain):
            continue
        label = skeleton.split(".")[-2] if "." in skeleton else skeleton
        if brand in skeleton or (len(label) >= 5 and SequenceMatcher(None, label, brand).ratio() >= 0.8):
            target = domain
            break
    return URLData(normalized_url=redact_url(normalized), hostname=host, typosquat_target=target,
        homograph_detected=bool(target and (unicode_host != skeleton or "xn--" in host)),
        confirmed_impersonation=bool(target), brand_impersonation=bool(target),
        suspicious_tld=host.rsplit(".", 1)[-1] in {"zip", "mov", "top", "xyz"},
        obfuscated=bool(parsed.username or re.search(r"%[0-9a-f]{2}", parsed.netloc, re.I) or host.count(".") > 4))
