"""
Clean Server Time Utilities - UTC ONLY
Simplified time management - chỉ sử dụng UTC:
- All timestamps in UTC
- No timezone confusion
- Clean and simple
"""

import time
import logging
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("server_time_utils")

# ========================================
# CORE TIME FUNCTIONS - UTC ONLY
# ========================================

def now() -> float:
    """Get current timestamp (Unix time)"""
    return time.time()

def now_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)

def now_iso() -> str:
    """Get current UTC time as ISO string"""
    return now_utc().isoformat()

def to_utc(dt: datetime) -> datetime:
    """Convert any datetime to UTC"""
    if dt is None:
        return None
    
    if dt.tzinfo is None:
        # Assume UTC if no timezone
        dt = dt.replace(tzinfo=timezone.utc)
    
    return dt.astimezone(timezone.utc)

def to_utc_naive(dt: datetime) -> datetime:
    """Convert datetime to UTC naive (for MongoDB storage)"""
    if dt is None:
        return None
    
    utc_dt = to_utc(dt)
    return utc_dt.replace(tzinfo=None)

def parse_agent_timestamp(iso_string: str) -> datetime:
    """
    Parse agent timestamp - always return UTC datetime
    """
    try:
        if not isinstance(iso_string, str):
            iso_string = str(iso_string)
        
        logger.debug(f"Parsing agent timestamp: '{iso_string}'")
        
        # Handle ISO format with timezone
        if 'T' in iso_string and ('+' in iso_string or 'Z' in iso_string):
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
            return dt.astimezone(timezone.utc)  # Always convert to UTC
        elif 'T' in iso_string:
            # ISO without timezone - assume UTC
            dt = datetime.fromisoformat(iso_string)
            return dt.replace(tzinfo=timezone.utc)
        else:
            # Handle simple formats
            formats_to_try = ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']
            for fmt in formats_to_try:
                try:
                    dt = datetime.strptime(iso_string, fmt)
                    return dt.replace(tzinfo=timezone.utc)  # Assume UTC
                except ValueError:
                    continue
            
            logger.warning(f"No format matched for '{iso_string}', using current time")
            return now_utc()
            
    except Exception as e:
        logger.warning(f"Failed to parse agent timestamp '{iso_string}': {e}")
        return now_utc()

# ========================================
# FORMATTING FUNCTIONS - UTC ONLY
# ========================================

def format_datetime(dt, format='%Y-%m-%d %H:%M:%S') -> str:
    """Format datetime object to string (UTC)"""
    if dt is None:
        return 'N/A'
    
    if isinstance(dt, str):
        try:
            dt = parse_agent_timestamp(dt)
        except:
            return dt
    
    if not isinstance(dt, datetime):
        return str(dt)
    
    try:
        # Convert to UTC if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        
        return dt.strftime(format)
    except Exception as e:
        logger.warning(f"Error formatting datetime {dt}: {e}")
        return str(dt)

def format_timestamp(timestamp: float, format='%Y-%m-%d %H:%M:%S') -> str:
    """Format Unix timestamp to string (UTC)"""
    if timestamp is None:
        return 'N/A'
    
    try:
        dt = datetime.fromtimestamp(timestamp, tz=timezone.utc)
        return dt.strftime(format)
    except Exception as e:
        logger.warning(f"Error formatting timestamp {timestamp}: {e}")
        return str(timestamp)

def is_recent(dt: datetime, minutes: int = 5) -> bool:
    """Check if datetime is recent (within specified minutes) - UTC"""
    if dt is None:
        return False
    
    try:
        # Convert to UTC if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        
        current = now_utc()
        time_diff = current - dt
        return time_diff.total_seconds() <= (minutes * 60)
        
    except Exception as e:
        logger.warning(f"Error checking if recent {dt}: {e}")
        return False

def calculate_age_seconds(dt: datetime) -> float:
    """Calculate age of datetime in seconds - UTC"""
    if dt is None:
        return 0.0
    
    try:
        # Convert to UTC if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        else:
            dt = dt.astimezone(timezone.utc)
        
        current = now_utc()
        time_diff = current - dt
        return time_diff.total_seconds()
        
    except Exception as e:
        logger.warning(f"Error calculating age for {dt}: {e}")
        return 0.0

def get_time_ago_string(dt: datetime) -> str:
    """Get human-readable "time ago" string - UTC"""
    if dt is None:
        return 'N/A'
    
    try:
        age_seconds = calculate_age_seconds(dt)
        
        if age_seconds < 60:
            return f"{int(age_seconds)} seconds ago"
        elif age_seconds < 3600:
            minutes = int(age_seconds / 60)
            return f"{minutes} minute{'s' if minutes != 1 else ''} ago"
        elif age_seconds < 86400:
            hours = int(age_seconds / 3600)
            return f"{hours} hour{'s' if hours != 1 else ''} ago"
        else:
            days = int(age_seconds / 86400)
            return f"{days} day{'s' if days != 1 else ''} ago"
            
    except Exception as e:
        logger.warning(f"Error getting time ago for {dt}: {e}")
        return str(dt)

# ========================================
# ALIASES FOR COMPATIBILITY
# ========================================

# Keep old function names for backward compatibility but make them UTC
now_vietnam = now_utc  # Now returns UTC
now_vietnam_naive = lambda: now_utc().replace(tzinfo=None)  # UTC naive
now_vietnam_iso = now_iso  # UTC ISO
parse_agent_timestamp_direct = parse_agent_timestamp  # UTC parsing

if __name__ == "__main__":
    # Test format functions
    print(" Testing format functions:")
    test_dt = now_utc().replace(tzinfo=None)
    print(f"format_datetime: {format_datetime(test_dt)}")
    print(f"format_timestamp: {format_timestamp(now())}")
    print(f"is_recent: {is_recent(test_dt)}")
    print(f"get_time_ago_string: {get_time_ago_string(test_dt)}")

