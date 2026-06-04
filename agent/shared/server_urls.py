"""Centralized agent → server URL resolver.

The agent has several components (registration, whitelist sync, heartbeat,
log sender) that need the list of server URLs to call. Historically each
one had its own resolver and silently fell back to ``http://localhost:5000``
when the user hadn't configured anything yet. That made "offline mode" mean
different things in different components: registration would skip, but
whitelist/heartbeat/log sender would happily contact a local address.

This module is the single source of truth. By default (production), an empty
config yields an empty list and the calling component must treat that as
"OFFLINE — skip work until the user sets a URL in Settings." A development
build (or test) may opt in to the localhost fallback explicitly.
"""

from typing import Dict, Iterable, List, Optional
from urllib.parse import urlparse, urlunparse

DEV_DEFAULT_URL = "http://localhost:5000"
KNOWN_UI_ROUTE_SEGMENTS = {"api-keys", "login", "dashboard", "settings"}


def normalize_server_url(url: str) -> str:
    """Normalize a user-entered controller URL to the API base URL.

    Settings help text points users at ``/api-keys`` to create a key, so it is
    natural for them to paste that whole browser URL into "Server URL". Runtime
    components append their own API paths, so known UI routes are stripped.
    Unknown paths are preserved because some deployments may mount SAINT under
    a subpath, for example ``https://example.edu/saint``.
    """
    stripped = str(url or "").strip()
    if not stripped:
        return ""

    parsed = urlparse(stripped)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return stripped.rstrip("/")

    path_parts = [part for part in parsed.path.split("/") if part]
    base_parts = path_parts
    for idx, part in enumerate(path_parts):
        if part.lower() in KNOWN_UI_ROUTE_SEGMENTS:
            base_parts = path_parts[:idx]
            break

    normalized_path = "/" + "/".join(base_parts) if base_parts else ""

    return urlunparse(
        (parsed.scheme.lower(), parsed.netloc, normalized_path, "", "", "")
    ).rstrip("/")


def collect_server_urls(config: Optional[Dict], allow_dev_default: bool = False) -> List[str]:
    """Return a deduplicated list of server URLs to try.

    Args:
        config: Agent config dict (may be None).
        allow_dev_default: When True and no URL is configured, return
            ``[DEV_DEFAULT_URL]`` so local dev/test runs keep working.
            Production callers MUST leave this False so an unconfigured
            agent silently stays offline instead of leaking to localhost.
    """
    urls: List[str] = []
    if not config:
        return [DEV_DEFAULT_URL] if allow_dev_default else []

    server_cfg = config.get("server") or {}

    raw_urls: Iterable = server_cfg.get("urls") or []
    if isinstance(raw_urls, (list, tuple)):
        urls.extend(str(u) for u in raw_urls)

    primary = server_cfg.get("url") or config.get("server_url")
    if primary:
        urls.append(str(primary))

    # Strip + dedupe, preserving order
    seen = set()
    cleaned: List[str] = []
    for u in urls:
        stripped = normalize_server_url(u)
        if not stripped or stripped in seen:
            continue
        seen.add(stripped)
        cleaned.append(stripped)

    if cleaned:
        return cleaned

    return [DEV_DEFAULT_URL] if allow_dev_default else []
