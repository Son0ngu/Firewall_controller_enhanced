"""
Time Utilities for Firewall Controller Agent

Centralized time management cho agent với các features:
- Consistent timestamp formats 
- UTC timestamps for server communication
- Cache-aware time functions
- Time validation and debugging
"""

import logging
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("time_utils")
VIETNAM_TIMEZONE = timezone(timedelta(hours=7))

# ========================================
# CORE TIME FUNCTIONS (simplified)
# ========================================

def now() -> float:
    """Unix timestamp."""
    return time.time()

def now_iso() -> str:
    """Local time ISO."""
    return datetime.now().isoformat()

def now_utc_iso() -> str:
    """UTC time ISO with Z."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

def now_vietnam_iso() -> str:
    """Vietnam time ISO."""
    return datetime.now(VIETNAM_TIMEZONE).isoformat()

# Alias for server compatibility
def now_server_compatible(ts: Optional[float] = None) -> str:
    """
    Return Vietnam ISO timestamp.
    Nếu ts được cung cấp (Unix timestamp), trả về thời gian tương ứng; nếu không, trả về thời gian hiện tại.
    """
    if ts is None:
        return now_vietnam_iso()
    return datetime.fromtimestamp(ts, VIETNAM_TIMEZONE).isoformat()

def sleep(duration: float):
    """Sleep with logging."""
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
# AGENT SPECIFIC (if needed)
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
# ALIASES FOR BACKWARD COMPATIBILITY
# ========================================

agent_time = now_vietnam_iso  # Agent time = Vietnam time
cache_time = now              # Cache time = Unix timestamp

def debug_time_info() -> dict:
    """Debug time information."""
    return {
        "unix": now(),
        "local": now_iso(),
        "utc": now_utc_iso(),
        "vietnam": now_vietnam_iso(),
        "uptime": uptime_string()
    }