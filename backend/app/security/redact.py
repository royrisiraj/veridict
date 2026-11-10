"""Minimize untrusted input before it reaches evidence, logs or external AI."""
import hashlib
import math
import re
from collections import Counter
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

from app.models import MessageData, MessageSpanEvidence

MASK = "[REDACTED]"
SENSITIVE_KEY = re.compile(r"token|key|secret|password|passwd|pwd|auth|jwt|session|code|sig|signature|api_key", re.I)
URL_PATTERN = re.compile(r"https?://[^\s<>\"']+", re.I)
SECRET_ASSIGNMENT = re.compile(r"\b(password|passwd|pwd|token|secret|api[_ -]?key|otp|verification code)\s*(?:[:=]|is\b)\s*[^\s,;]+", re.I)
PATTERNS = {
    "urgency": r"\b(urgent|immediately|action required|within \d+ minutes|suspended|act now)\b",
    "credential_harvesting": r"\b(password|log[ -]?in|sign[ -]?in|credentials?|verify your account)\b",
    "otp_request": r"\b(OTP|2FA code|verification code|one[ -]?time (?:code|password))\b",
    "seed_phrase_request": r"\b(seed phrase|recovery phrase|12[ -]word|24[ -]word)\b",
    "payment_lure": r"\b(wire transfer|send money|payment required|claim your prize|pay now)\b",
    "brand_impersonation": r"\b(paypal|microsoft|google|apple|bank(?:ing)?|coinbase)\b",
}


def high_entropy(value: str) -> bool:
    if len(value) < 24:
        return False
    counts = Counter(value)
    entropy = -sum((n / len(value)) * math.log2(n / len(value)) for n in counts.values())
    return entropy > 3.5 and bool(re.search(r"\d", value))


def redact_url(raw_url: str) -> str:
    try:
        parsed = urlsplit(raw_url)
        host = parsed.hostname or ""
        host = f"[{host}]" if ":" in host else host
        port = f":{parsed.port}" if parsed.port else ""
        query = [(k, MASK if SENSITIVE_KEY.search(k) or high_entropy(v) else redact_text(v, urls=False)) for k, v in parse_qsl(parsed.query, keep_blank_values=True)]
        # Fragments are client-only and can contain OAuth tokens; discard them.
        path = re.sub(r"[A-Za-z0-9_=-]{24,}", lambda m: MASK if high_entropy(m[0]) else m[0], parsed.path)
        path = re.sub(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", MASK, path)
        path = re.sub(r"(/(?:password|token|secret|api_key)/)[^/]+", lambda m: m[1] + MASK, path, flags=re.I)
        path = redact_text(path, urls=False)
        return urlunsplit((parsed.scheme.lower(), host + port, path, urlencode(query, quote_via=quote, safe="[]"), ""))
    except (ValueError, UnicodeError):
        return "[INVALID_URL]"


def redact_text(text: str, *, urls: bool = True) -> str:
    if urls:
        text = URL_PATTERN.sub(lambda m: redact_url(m[0]), text)
    text = SECRET_ASSIGNMENT.sub(lambda m: m[1] + "=" + MASK, text)
    text = re.sub(r"\bBearer\s+\S+", "Bearer " + MASK, text, flags=re.I)
    # Phrase requests are preserved, but the supplied phrase is removed wholesale.
    text = re.sub(r"((?:seed|recovery) phrase\s*[:=]\s*)(?:[A-Za-z]+[ \t]+){11,23}[A-Za-z]+", lambda m: m[1] + MASK, text, flags=re.I)
    text = re.sub(r"\b(?:[a-z]+[ \t]+){23}[a-z]+\b", MASK, text)
    text = re.sub(r"\b(?:[a-z]+[ \t]+){11}[a-z]+\b", MASK, text)
    text = re.sub(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b", MASK, text)
    text = re.sub(r"(?<!\w)\+?\d[\d ()-]{7,}\d(?!\w)", MASK, text)
    text = re.sub(r"\b[A-Za-z0-9_./+=-]{24,}\b", lambda m: MASK if high_entropy(m[0]) else m[0], text)
    return text


def extract_message_spans(raw_message: str, mode: str = "local") -> list[MessageSpanEvidence]:
    spans = []
    # Offset/hash refer to original text; excerpts never do.
    for pattern_type, pattern in PATTERNS.items():
        for match in re.finditer(pattern, raw_message, re.I):
            spans.append(MessageSpanEvidence(
                id=f"msg:{len(spans) + 1}", type="message_span", status="COMPLETE", mode=mode,
                data=MessageData(start=match.start(), end=match.end(), pattern_type=pattern_type,
                    sha256=hashlib.sha256(match[0].encode()).hexdigest(),
                    redacted_excerpt=redact_text(raw_message)[:600]),
            ))
            if len(spans) == 50:
                return spans
    return spans


def redact_sensitive_data(raw_url: str, raw_message: str | None) -> tuple[str, list[MessageSpanEvidence]]:
    return redact_url(raw_url), extract_message_spans(raw_message or "")
