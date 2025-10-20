"""
Time Utilities for Firewall Controller Agent 

Simplified time management 
- All timestamps in UTC
"""

import logging
import time
from datetime import datetime
from typing import Optional
from zoneinfo import ZoneInfo

logger = logging.getLogger("time_utils")

# ========================================
# CORE TIME FUNCTIONS 
# ========================================

def now() -> float:
    """Unix timestamp (always UTC)."""
    return time.time()

def now_iso() -> str:
    """UTC time ISO with Z suffix."""
    return datetime.now(VIETNAM_TZ).isoformat()

def now_server_compatible(ts: Optional[float] = None) -> str:
    """
    Return UTC ISO timestamp.
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