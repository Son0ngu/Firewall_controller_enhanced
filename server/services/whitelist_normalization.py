"""Whitelist entry canonicalization for server-side writes and sync."""

from ipaddress import ip_address
from typing import Tuple
from urllib.parse import urlparse


def _looks_url_like(value: str) -> bool:
    raw = str(value or "").strip()
    parsed = urlparse(raw)
    return bool(
        (parsed.scheme and parsed.netloc)
        or "/" in raw
        or "?" in raw
        or "#" in raw
    )


def normalize_whitelist_host(value: str) -> str:
    raw = str(value or "").strip().lower()
    if not raw:
        return ""

    parse_target = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlparse(parse_target)
        host = parsed.hostname or ""
    except ValueError:
        host = ""

    if not host:
        host = raw.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if ":" in host and host.count(":") == 1:
            host = host.split(":", 1)[0]

    return host.strip().strip(".")


def is_ip_literal(value: str) -> bool:
    try:
        ip_address(str(value or "").strip())
        return True
    except ValueError:
        return False


def canonicalize_whitelist_entry(entry_type: str, value: str) -> Tuple[str, str]:
    raw_type = str(entry_type or "domain").strip().lower()
    raw_value = str(value or "").strip().lower()
    if not raw_value:
        return raw_type or "domain", ""

    if raw_type == "url" and not _looks_url_like(raw_value):
        # Preserve legacy URL validation: "not-a-url" should still fail as a
        # URL instead of being accepted as a bare domain.
        return raw_type, raw_value

    should_normalize = (
        raw_type in {"domain", "url", "pattern"}
        or "/" in raw_value
        or "?" in raw_value
        or "#" in raw_value
        or "://" in raw_value
    )
    normalized = normalize_whitelist_host(raw_value) if should_normalize else raw_value
    if not normalized:
        return raw_type, ""

    if raw_type == "url":
        raw_type = "domain"

    if raw_type == "ip" or is_ip_literal(normalized):
        return "ip", normalized

    if "*" in normalized:
        return "pattern", normalized

    return "domain", normalized
