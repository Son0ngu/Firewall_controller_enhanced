"""Canonicalization helpers for whitelist values.

Whitelist enforcement in the agent is host/IP based. Admins may paste a full
browser URL (including OAuth query strings), but packet capture and firewall
rules operate on hostnames and IPs, not paths or query parameters.
"""

from ipaddress import ip_address
from typing import Tuple
from urllib.parse import urlparse


def normalize_whitelist_host(value: str) -> str:
    """Return a lowercase hostname/IP/wildcard host from a whitelist value."""
    raw = str(value or "").strip().lower()
    if not raw:
        return ""

    # Treat bare hosts with path/query/port as URL authorities by prefixing
    # "//". urlparse then exposes hostname without scheme/path/query/fragment.
    parse_target = raw if "://" in raw else f"//{raw}"
    try:
        parsed = urlparse(parse_target)
        host = parsed.hostname or ""
    except ValueError:
        host = ""

    if not host:
        # Conservative fallback for malformed inputs: remove URL-ish tails.
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
    """Return (type, value) normalized for agent-side matching.

    URL entries become their host. A question mark is *not* a wildcard; it is
    normally part of a query string and has already been stripped. Hostname
    wildcard support is limited to "*" patterns such as "*.example.com".
    """
    normalized = normalize_whitelist_host(value)
    if not normalized:
        return "", ""

    raw_type = str(entry_type or "domain").strip().lower()
    if raw_type == "url":
        raw_type = "domain"

    if raw_type == "ip" or is_ip_literal(normalized):
        return "ip", normalized

    if "*" in normalized:
        return "pattern", normalized

    # A caller may label a full URL as "pattern"; once it normalizes to an
    # exact hostname, treat it as a domain so it can match and resolve.
    return "domain", normalized
