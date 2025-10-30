"""
Time Utilities for Firewall Controller Agent 

Simplified time management 
- All timestamps in vietnam
"""

import logging
import time
from datetime import datetime, timedelta, timezone, tzinfo
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger("time_utils")
def _load_vietnam_timezone() -> tzinfo:
    """Return the Vietnam timezone, falling back to a fixed offset.

    Python's :mod:`zoneinfo` requires the ``tzdata`` package on systems that do
    not ship the IANA timezone database (for example, Windows or some minimal
    containers).  When that package is missing the agent previously crashed at
    import time.  To keep the agent functional we log the issue and fall back to
    a fixed UTC+7 offset which is accurate for Ho Chi Minh City.
    """

    try:
        return ZoneInfo("Asia/Ho_Chi_Minh")
    except ZoneInfoNotFoundError:
        logger.warning(
            "tzdata package is missing; falling back to fixed UTC+7 offset for Asia/Ho_Chi_Minh"
        )
        return timezone(timedelta(hours=7), name="Asia/Ho_Chi_Minh")


# ========================================
# CORE TIME FUNCTIONS 
# ========================================
VIETNAM_TZ = _load_vietnam_timezone()
def now() -> float:
    """Unix timestamp (always vietnam)."""
    return time.time()

def now_vietnam() -> datetime:
    """Get current Vietnam datetime (Asia/Ho_Chi_Minh)."""
    return datetime.now(VIETNAM_TZ)

def now_iso() -> str:
    """vietnam time ISO with Z suffix."""
    return datetime.now(VIETNAM_TZ).isoformat()

def now_server_compatible(ts: Optional[float] = None) -> str:
    """
    Return vietnam ISO timestamp.
    """
    if ts is None:
        return now_iso()
    return datetime.fromtimestamp(ts, VIETNAM_TZ).isoformat()

def sleep(duration: float):
    """Sleep function."""
    if duration > 0:
        time.sleep(duration)

# ========================================
# CACHE & VALIDATION
# ========================================

def is_cache_valid(timestamp: float, ttl: float) -> bool:
    """Check if cache is still valid."""
    return (now() - timestamp) < ttl

def cache_age(timestamp: float) -> float:
    """Get cache age in seconds."""
    return now() - timestamp

# ========================================
# AGENT UPTIME
# ========================================

_start_time = now()

def uptime() -> float:
    """Agent uptime in seconds."""
    return now() - _start_time

def uptime_string() -> str:
    """Agent uptime as readable string."""
    secs = uptime()
    hours = int(secs // 3600)
    mins = int((secs % 3600) // 60)
    secs = int(secs % 60)
    return f"{hours}h {mins}m {secs}s"

# ========================================
# ALIASES FOR COMPATIBILITY
# ========================================

# Maintain compatibility aliases
agent_time = now_iso
cache_time = now

def debug_time_info() -> dict:
    """Debug time information """
    return {
        "unix": now(),
        "vietnam_iso": now_iso(),
        "uptime": uptime_string()
    }