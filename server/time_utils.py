"""
Clean Server Time Utilities - COMPLETE VERSION
"""

import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger("server_time_utils")

# ========================================
# TIMEZONE CONFIGURATION
# ========================================

VIETNAM_TIMEZONE = timezone(timedelta(hours=7))

# ========================================
# CORE TIME FUNCTIONS
# ========================================

def now() -> float:
    """Get current timestamp (Unix time)"""
    return time.time()

def now_utc() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)

def now_vietnam() -> datetime:
    """Get current Vietnam datetime (UTC+7)"""
    return datetime.now(VIETNAM_TIMEZONE)

def now_vietnam_naive() -> datetime:
    """Get current Vietnam time as naive datetime (for MongoDB)"""
    vietnam_time = now_vietnam()
    return vietnam_time.replace(tzinfo=None)

def now_vietnam_iso() -> str:
    """Get current Vietnam time as ISO string"""
    return now_vietnam().isoformat()

def to_vietnam_timezone(dt: datetime) -> datetime:
    """Convert any datetime to Vietnam timezone"""
    if dt is None:
        return None
    
    if dt.tzinfo is None:
        # Assume UTC if no timezone
        dt = dt.replace(tzinfo=timezone.utc)
    
    return dt.astimezone(VIETNAM_TIMEZONE)

def to_vietnam_naive(dt: datetime) -> datetime:
    """Convert datetime to Vietnam naive (for MongoDB storage)"""
    if dt is None:
        return None
    
    vietnam_dt = to_vietnam_timezone(dt)
    return vietnam_dt.replace(tzinfo=None)

def parse_agent_timestamp_direct(iso_string: str) -> datetime:
    """
    Parse agent timestamp.
    Nếu agent gửi format có timezone, trả về datetime với timezone đó.
    Nếu chỉ nhận được format không có timezone, ASSUME UTC và convert ra giờ VN.
    """
    try:
        if not isinstance(iso_string, str):
            iso_string = str(iso_string)
        
        logger.debug(f"Parsing agent timestamp: '{iso_string}'")
        
        # Nếu có dấu "T" và ("+" hoặc "Z")
        if 'T' in iso_string and ('+' in iso_string or 'Z' in iso_string):
            dt = datetime.fromisoformat(iso_string.replace('Z', '+00:00'))
            if '+07:00' in iso_string:
                # Nếu có múi giờ VN thì giữ nguyên (không remove tzinfo)
                logger.debug(f"Vietnam timezone detected: {dt}")
                return dt  # Giữ dt có tzinfo
            else:
                # Nếu không phải VN → chuyển về giờ VN
                logger.debug(f"Converting {dt} to Vietnam timezone")
                vn_time = dt.astimezone(VIETNAM_TIMEZONE)
                return vn_time
        elif 'T' in iso_string:
            dt = datetime.fromisoformat(iso_string)
            logger.debug(f"ISO without timezone, assuming UTC: {dt}")
            utc_dt = dt.replace(tzinfo=timezone.utc)
            vn_time = utc_dt.astimezone(VIETNAM_TIMEZONE)
            return vn_time
        else:
            # Xử lý format đơn giản
            formats_to_try = ['%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S']
            for fmt in formats_to_try:
                try:
                    dt = datetime.strptime(iso_string, fmt)
                    logger.debug(f"Matched format '{fmt}': {dt}")
                    # Assume old data là UTC
                    utc_dt = dt.replace(tzinfo=timezone.utc)
                    vn_time = utc_dt.astimezone(VIETNAM_TIMEZONE)
                    return vn_time
                except ValueError:
                    continue
            logger.warning(f"No format matched for '{iso_string}', using current time")
            return now_vietnam()
    except Exception as e:
        logger.warning(f"Failed to parse agent timestamp '{iso_string}': {e}")
        return now_vietnam()

# ========================================
# FORMATTING FUNCTIONS
# ========================================

def format_datetime(dt, format='%Y-%m-%d %H:%M:%S') -> str:
    """
    Format datetime object to string
    
    Args:
        dt: datetime object or string
        format: strftime format string
        
    Returns:
        str: Formatted datetime string
    """
    if dt is None:
        return 'N/A'
    
    if isinstance(dt, str):
        try:
            # Try to parse if it's a string
            dt = parse_agent_timestamp_direct(dt)
        except:
            return dt
    
    if not isinstance(dt, datetime):
        return str(dt)
    
    try:
        return dt.strftime(format)
    except Exception as e:
        logger.warning(f"Error formatting datetime {dt}: {e}")
        return str(dt)

def format_timestamp(timestamp: float, format='%Y-%m-%d %H:%M:%S') -> str:
    """
    Format Unix timestamp to string
    
    Args:
        timestamp: Unix timestamp
        format: strftime format string
        
    Returns:
        str: Formatted timestamp string (Vietnam time)
    """
    if timestamp is None:
        return 'N/A'
    
    try:
        # Convert to Vietnam datetime
        dt = datetime.fromtimestamp(timestamp, tz=VIETNAM_TIMEZONE)
        return dt.strftime(format)
    except Exception as e:
        logger.warning(f"Error formatting timestamp {timestamp}: {e}")
        return str(timestamp)

def is_recent(dt: datetime, minutes: int = 5) -> bool:
    """
    Check if datetime is recent (within specified minutes)
    
    Args:
        dt: datetime to check
        minutes: minutes threshold
        
    Returns:
        bool: True if recent
    """
    if dt is None:
        return False
    
    try:
        # Convert to Vietnam timezone if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=VIETNAM_TIMEZONE)
        
        current = now_vietnam()
        time_diff = current - dt
        return time_diff.total_seconds() <= (minutes * 60)
        
    except Exception as e:
        logger.warning(f"Error checking if recent {dt}: {e}")
        return False

def calculate_age_seconds(dt: datetime) -> float:
    """
    Calculate age of datetime in seconds
    
    Args:
        dt: datetime to calculate age for
        
    Returns:
        float: Age in seconds
    """
    if dt is None:
        return 0.0
    
    try:
        # Convert to Vietnam timezone if needed
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=VIETNAM_TIMEZONE)
        
        current = now_vietnam()
        time_diff = current - dt
        return time_diff.total_seconds()
        
    except Exception as e:
        logger.warning(f"Error calculating age for {dt}: {e}")
        return 0.0

def get_time_ago_string(dt: datetime) -> str:
    """
    Get human-readable "time ago" string
    
    Args:
        dt: datetime to calculate for
        
    Returns:
        str: Human readable time ago string
    """
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
# DEBUG FUNCTIONS
# ========================================

def get_time_info() -> dict:
    """Get comprehensive time information for debugging"""
    current_utc = now_utc()
    current_vietnam = now_vietnam()
    current_naive = now_vietnam_naive()
    
    return {
        "current_utc": current_utc.isoformat(),
        "current_vietnam": current_vietnam.isoformat(),
        "current_vietnam_naive": current_naive.isoformat(),
        "current_timestamp": now(),
        "timezone_offset": "+07:00"
    }

def debug_time_info():
    """Print time debug information"""
    info = get_time_info()
    print("🕐 Server Time Debug Info:")
    print(f"   UTC Time: {info['current_utc']}")
    print(f"   Vietnam Time: {info['current_vietnam']}")
    print(f"   Vietnam Naive: {info['current_vietnam_naive']}")
    print(f"   Timestamp: {info['current_timestamp']}")
    print(f"   Timezone: {info['timezone_offset']}")

if __name__ == "__main__":
    # Test functions when run directly
    debug_time_info()
    print()
    
    # Test format functions
    print("🧪 Testing format functions:")
    test_dt = now_vietnam_naive()
    print(f"format_datetime: {format_datetime(test_dt)}")
    print(f"format_timestamp: {format_timestamp(now())}")
    print(f"is_recent: {is_recent(test_dt)}")
    print(f"get_time_ago_string: {get_time_ago_string(test_dt)}")

