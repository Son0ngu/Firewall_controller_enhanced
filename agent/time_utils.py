"""
Time Utilities for Firewall Controller Agent - UTC ONLY

Simplified time management - chỉ sử dụng UTC:
- All timestamps in UTC
- No timezone confusion
- Clean and simple
"""

import logging
import time
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("time_utils")

# ========================================
# CORE TIME FUNCTIONS - UTC ONLY
# ========================================

def now() -> float:
    """Unix timestamp (always UTC)."""
    return time.time()

def now_iso() -> str:
    """UTC time ISO with Z suffix."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def now_utc_iso() -> str:
    """Same as now_iso() - for compatibility."""
    return now_iso()

def now_server_compatible(ts: Optional[float] = None) -> str:
    """
    Return UTC ISO timestamp.
    """
    if ts is None:
        return now_iso()
    return datetime.fromtimestamp(ts, timezone.utc).isoformat().replace('+00:00', 'Z')

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

# Remove Vietnam aliases
agent_time = now_iso
cache_time = now

def debug_time_info() -> dict:
    """Debug time information - UTC only."""
    return {
        "unix": now(),
        "utc_iso": now_iso(),
        "uptime": uptime_string()
    }