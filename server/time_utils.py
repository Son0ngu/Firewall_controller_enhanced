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
from datetime import datetime, timedelta
from typing import Any
from zoneinfo import ZoneInfo
logger = logging.getLogger("server_time_utils")


VIETNAM_TZ = ZoneInfo("Asia/Ho_Chi_Minh")
FUTURE_DRIFT_TOLERANCE = timedelta(minutes=5)

# =========================
# Core helpers
# =========================

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


def _normalise_future_timestamp(dt: datetime, *, reference: datetime | None = None) -> datetime:
    """Clamp timestamps that sit unreasonably far in the future.

    Some historical records were stored in UTC and then converted twice,
    effectively pushing them ~7 hours ahead of the real heartbeat time. To
    keep status calculations stable we detect that drift and either subtract
    the timezone offset (when that fixes the problem) or clamp the value to
    the current server time.
    """

    reference_time = reference or now_vietnam()
    drift = dt - reference_time
    drift_seconds = drift.total_seconds()

    if drift_seconds <= FUTURE_DRIFT_TOLERANCE.total_seconds():
        return dt

    offset = dt.utcoffset()
    if offset:
        candidate = dt - offset
        candidate_drift = candidate - reference_time
        candidate_seconds = abs(candidate_drift.total_seconds())

        if candidate_seconds < abs(drift_seconds):
            if candidate_seconds <= FUTURE_DRIFT_TOLERANCE.total_seconds():
                logger.warning(
                    "Timestamp %s ahead of reference %s by %s; correcting by removing offset %s",
                    dt,
                    reference_time,
                    drift,
                    offset,
                )
            else:
                logger.warning(
                    "Timestamp %s ahead of reference %s by %s; removing offset %s leaves residual drift %s",
                    dt,
                    reference_time,
                    drift,
                    offset,
                    candidate_drift,
                )
            return candidate

    logger.warning(
        "Timestamp %s ahead of reference %s by %s; clamping to reference",
        dt,
        reference_time,
        drift,
    )
    return reference_time

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
        parsed = to_vietnam(value)
        return _normalise_future_timestamp(parsed)

    if isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(value, tz=VIETNAM_TZ)
        return _normalise_future_timestamp(parsed)
    
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
        parsed = to_vietnam(parsed)
        return _normalise_future_timestamp(parsed)
    except ValueError:
        fallback = _parse_with_known_formats(text_value)
        if fallback is not None:
            parsed = to_vietnam(fallback)
            return _normalise_future_timestamp(parsed)

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


