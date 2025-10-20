"""
Clean Server Time Utilities - vietnam ONLY
Simplified time management - chỉ sử dụng vietnam:
- All timestamps in vietnam
- No timezone confusion
- Clean and simple
"""

import time
import logging
from datetime import datetime
from zoneinfo import ZoneInfo
logger = logging.getLogger("server_time_utils")

# ========================================
# CORE TIME FUNCTIONS - VIETNAM TIMEZONE
# ========================================
VIETNAM_TZ = ZoneInfo("Asia/Ho_Chi_Minh")

def now() -> float:
    """Get current timestamp (Unix time)"""
    return time.time()
def now_vietnam() -> datetime:
    """Get current Vietnam datetime (Asia/Ho_Chi_Minh)."""
    return datetime.now(VIETNAM_TZ)

def now_iso() -> str:
    """Get current Vietnam time as ISO string"""
    return now_vietnam().isoformat()

def to_vietnam(dt: datetime) -> datetime:
    """Convert any datetime to Vietnam time"""
    if dt is None:
        return None
    
    if dt.tzinfo is None:
         # Assume current Vietnam timezone if no timezone
        dt = dt.replace(tzinfo=VIETNAM_TZ)

    return dt.astimezone(VIETNAM_TZ)

def to_vietnam_naive(dt: datetime) -> datetime:
    """Convert datetime to Vietnam naive (for MongoDB storage)"""
    if dt is None:
        return None
    
    vietnam_dt = to_vietnam(dt)
    return vietnam_dt.replace(tzinfo=None)

def parse_agent_timestamp(iso_string: str) -> datetime:
    """
    Parse agent timestamp - always return vietnam datetime
    """
    try:
        if not isinstance(iso_string, str):
            iso_string = str(iso_string)
        
        logger.debug(f"Parsing agent timestamp: '{iso_string}'")
        
        # Handle ISO format with timezone
        if 'T' in iso_string and ('+' in iso_string or 'Z' in iso_string):
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
            return dt.astimezone(VIETNAM_TZ)  # Always convert to vietnam
        elif 'T' in iso_string:
            # ISO without timezone - assume vietnam
            dt = datetime.fromisoformat(iso_string)
            return dt.replace(tzinfo=VIETNAM_TZ)
        else:
            # Handle simple formats
            formats_to_try = ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']
            for fmt in formats_to_try:
                try:
                    dt = datetime.strptime(iso_string, fmt)
                    return dt.replace(tzinfo=VIETNAM_TZ)  # Assume vietnam
                except ValueError:
                    continue
            
            logger.warning(f"No format matched for '{iso_string}', using current time")
            return now_vietnam()
            
    except Exception as e:
        logger.warning(f"Failed to parse agent timestamp '{iso_string}': {e}")
        return now_vietnam()

# ========================================
# FORMATTING FUNCTIONS - vietnam ONLY
# ========================================

def format_datetime(dt, format='%Y-%m-%d %H:%M:%S') -> str:
    """Format datetime object to string (vietnam)"""
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
        # Convert to vietnam if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=VIETNAM_TZ)
        else:
            dt = dt.astimezone(VIETNAM_TZ)
        
        return dt.strftime(format)
    except Exception as e:
        logger.warning(f"Error formatting datetime {dt}: {e}")
        return str(dt)

def format_timestamp(timestamp: float, format='%Y-%m-%d %H:%M:%S') -> str:
    """Format Unix timestamp to string (vietnam)"""
    if timestamp is None:
        return 'N/A'
    
    try:
        dt = datetime.fromtimestamp(timestamp, tz=VIETNAM_TZ)
        return dt.strftime(format)
    except Exception as e:
        logger.warning(f"Error formatting timestamp {timestamp}: {e}")
        return str(timestamp)

def is_recent(dt: datetime, minutes: int = 5) -> bool:
    """Check if datetime is recent (within specified minutes) - vietnam"""
    if dt is None:
        return False
    
    try:
        # Convert to vietnam if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=VIETNAM_TZ)
        else:
            dt = dt.astimezone(VIETNAM_TZ)
        
        current = now_vietnam()
        time_diff = current - dt
        return time_diff.total_seconds() <= (minutes * 60)
        
    except Exception as e:
        logger.warning(f"Error checking if recent {dt}: {e}")
        return False

def calculate_age_seconds(dt: datetime) -> float:
    """Calculate age of datetime in seconds - vietnam"""
    if dt is None:
        return 0.0
    
    try:
        # Convert to vietnam if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=VIETNAM_TZ)
        else:
            dt = dt.astimezone(VIETNAM_TZ)
        
        current = now_vietnam()
        time_diff = current - dt
        return time_diff.total_seconds()
        
    except Exception as e:
        logger.warning(f"Error calculating age for {dt}: {e}")
        return 0.0

def get_time_ago_string(dt: datetime) -> str:
    """Get human-readable "time ago" string - vietnam"""
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

# Keep alias for backward compatibility in vietnam
parse_agent_timestamp_direct = parse_agent_timestamp  # vietnam parsing

if __name__ == "__main__":
    # Test format functions
    print(" Testing format functions:")
    test_dt = now_vietnam().replace(tzinfo=None)
    print(f"format_datetime: {format_datetime(test_dt)}")
    print(f"format_timestamp: {format_timestamp(now())}")
    print(f"is_recent: {is_recent(test_dt)}")
    print(f"get_time_ago_string: {get_time_ago_string(test_dt)}")

