"""Utility helpers for working with Vietnam local time.

All components (server, agent, background jobs) operate using the same
Vietnam timezone.  To keep things simple we deal exclusively with
timezone-aware ``datetime`` instances that carry the ``Asia/Ho_Chi_Minh``
offset.  The helpers in this module therefore focus on three tasks:

* provide "now" helpers for convenience,
* normalise arbitrary timestamp inputs so that calculations always work on the
  same timezone, and
* offer lightweight formatting utilities for presenting timestamps.

Because everything already speaks the same timezone there is no need to convert
back and forth between naive datetimes any more.
"""

from __future__ import annotations
import logging
import time
from datetime import datetime
from typing import Any
from zoneinfo import ZoneInfo
logger = logging.getLogger("server_time_utils")


VIETNAM_TZ = ZoneInfo("Asia/Ho_Chi_Minh")

# =========================
# Core helpers
# =========================

def now() -> float:
    """Return the current Unix timestamp."""
    return time.time()
def now_vietnam() -> datetime:
    """Return the current datetime in Vietnam (timezone aware)."""
    return datetime.now(VIETNAM_TZ)

def now_iso() -> str:
    """Return the current Vietnam time as an ISO 8601 string."""
    return now_vietnam().isoformat()

def to_vietnam(dt: datetime | None) -> datetime | None:
    """Ensure ``dt`` is expressed in the Vietnam timezone."""

    if dt is None:
        return None
    
    if dt.tzinfo is None:
        return dt.replace(tzinfo=VIETNAM_TZ)

    return dt.astimezone(VIETNAM_TZ)

def _parse_with_known_formats(value: str) -> datetime | None:
    """Try to parse ``value`` using a list of known datetime formats."""

    formats_to_try = [
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d %H:%M:%S",
    ]

    for fmt in formats_to_try:
        try:
            parsed = datetime.strptime(value, fmt)
            return parsed.replace(tzinfo=VIETNAM_TZ)
        except ValueError:
            continue

    return None


def parse_agent_timestamp(value: Any) -> datetime:
    """Normalise any timestamp sent by an agent to Vietnam local time."""

    if value is None:
        return now_vietnam()

    if isinstance(value, datetime):
        return to_vietnam(value)

    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=VIETNAM_TZ)
    
    try:
        text_value = str(value).strip()
    except Exception:  # pragma: no cover - defensive
        logger.warning("Failed to convert %r to string when parsing timestamp", value)
        return now_vietnam()

    if not text_value:
        return now_vietnam()

    try:
        iso_ready = text_value.replace("Z", "+00:00")
        parsed = datetime.fromisoformat(iso_ready)
        return to_vietnam(parsed)
    except ValueError:
        fallback = _parse_with_known_formats(text_value)
        if fallback is not None:
            return fallback

        logger.warning("Unrecognised timestamp '%s', defaulting to current time", text_value)
        return now_vietnam()
    
# =========================
# Formatting helpers
# =========================

def format_datetime(value: Any, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format ``value`` (string or datetime) using Vietnam local time."""

    if value is None:
        return "N/A"

    if not isinstance(value, datetime):

        try:
            value = parse_agent_timestamp(value)
        except Exception:  # pragma: no cover - defensive
            return str(value)
    else:
        value = to_vietnam(value)
    
    try:
        return value.strftime(fmt)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Error formatting datetime %r: %s", value, exc)
        return str(value)


def format_timestamp(timestamp: float, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Format a Unix timestamp using the Vietnam timezone."""
    if timestamp is None:
        return "N/A"
    
    try:
        dt = datetime.fromtimestamp(timestamp, tz=VIETNAM_TZ)
        return dt.strftime(fmt)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Error formatting timestamp %r: %s", timestamp, exc)
        return str(timestamp)

def is_recent(value: Any, minutes: int = 5) -> bool:
    """Return ``True`` if ``value`` occurred within ``minutes`` minutes."""
    
    try:
        dt = parse_agent_timestamp(value)
        return (now_vietnam() - dt).total_seconds() <= minutes * 60
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Error checking recency for %r: %s", value, exc)
        return False

def calculate_age_seconds(value: Any) -> float:
    """Return the age of ``value`` in seconds relative to Vietnam time."""

    try:
        dt = parse_agent_timestamp(value)
        return (now_vietnam() - dt).total_seconds()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Error calculating age for %r: %s", value, exc)
        return 0.0

def get_time_ago_string(value: Any) -> str:
    """Return a human readable "time ago" string for ``value``."""

    age_seconds = calculate_age_seconds(value)

    if age_seconds <= 0:
        return "just now"

    if age_seconds < 60:
        return f"{int(age_seconds)} seconds ago"
    if age_seconds < 3600:
        minutes = int(age_seconds / 60)
        return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
    if age_seconds < 86400:
        hours = int(age_seconds / 3600)
        return f"{hours} hour{'s' if hours != 1 else ''} ago"

    days = int(age_seconds / 86400)
    return f"{days} day{'s' if days != 1 else ''} ago"


# ==========================
# Compatibility aliases
# ==========================

parse_agent_timestamp_direct = parse_agent_timestamp


if __name__ == "__main__":  # pragma: no cover - simple smoke test
    print("Testing time utilities")
    sample = now_vietnam()
    print(" now_iso() =>", now_iso())
    print(" format_datetime() =>", format_datetime(sample))
    print(" get_time_ago_string() =>", get_time_ago_string(sample))

