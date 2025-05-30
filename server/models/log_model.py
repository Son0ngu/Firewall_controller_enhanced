"""
Log Model - handles log data operations
"""

from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
import logging

logger = logging.getLogger(__name__)

class LogModel:
    """Model for log data operations"""
    
    def __init__(self, db: Database):
        self.db = db
        self.collection: Collection = db.logs
        
        # ✅ FIX: Add logger instance
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # ✅ FIXED: Force UTC+7 timezone for Vietnam
        self.vietnam_timezone = timezone(timedelta(hours=7), name="UTC+7")
        self._create_indexes()
        
        self.logger.info(f"LogModel initialized with Vietnam timezone: {self.vietnam_timezone}")
    
    def _get_vietnam_timezone(self) -> timezone:
        """Get Vietnam timezone (UTC+7)"""
        return timezone(timedelta(hours=7), name="UTC+7")
    
    def _now_local(self) -> datetime:
        """Get current time in Vietnam timezone"""
        # ✅ FIX: Always get UTC time first, then convert to Vietnam
        utc_now = datetime.now(timezone.utc)
        vn_time = utc_now.astimezone(self.vietnam_timezone)
        
        # ✅ DEBUG: Log time calculation
        self.logger.debug(f"UTC time: {utc_now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        self.logger.debug(f"VN time:  {vn_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        
        return vn_time
    
    def _ensure_vietnam_timezone(self, dt: datetime) -> datetime:
        """Ensure datetime is in Vietnam timezone"""
        if dt is None:
            return None
            
        if dt.tzinfo is None:
            # ✅ FIX: Naive datetime handling
            # Check if this might already be Vietnam time
            current_utc = datetime.now(timezone.utc)
            current_vn = current_utc.astimezone(self.vietnam_timezone)
            
            # If the naive time is close to Vietnam time, assume it's Vietnam
            if abs((dt.hour - current_vn.hour) % 24) <= 1:
                return dt.replace(tzinfo=self.vietnam_timezone)
            else:
                # Otherwise, treat as UTC and convert
                dt_utc = dt.replace(tzinfo=timezone.utc)
                return dt_utc.astimezone(self.vietnam_timezone)
        else:
            # Convert to Vietnam timezone
            return dt.astimezone(self.vietnam_timezone)
    
    def _create_indexes(self):
        """Create necessary indexes for performance"""
        try:
            # Index for timestamp (most common query)
            self.collection.create_index([("timestamp", DESCENDING)])
            
            # Index for agent_id
            self.collection.create_index([("agent_id", ASCENDING)])
            
            # Index for action
            self.collection.create_index([("action", ASCENDING)])
            
            # Index for domain
            self.collection.create_index([("domain", ASCENDING)])
            
            # Compound index for common queries
            self.collection.create_index([
                ("action", ASCENDING),
                ("timestamp", DESCENDING)
            ])
            
            self.logger.info("Log indexes created successfully")
            
        except Exception as e:
            self.logger.warning(f"Could not create log indexes: {e}")
    
    def count_logs(self, query: Dict = None) -> int:
        """Count logs with error handling and debugging"""
        try:
            if query is None:
                query = {}
            
            self.logger.debug(f"Counting logs with query: {query}")
            count = self.collection.count_documents(query)
            self.logger.debug(f"Log count result: {count}")
            
            return count
            
        except Exception as e:
            self.logger.error(f"Error counting logs with query {query}: {e}")
            return 0

    def find_all_logs(self, query: Dict = None, limit: int = 100, offset: int = 0) -> List[Dict]:
        """Find all logs with enhanced debugging"""
        try:
            if query is None:
                query = {}
            
            self.logger.debug(f"Finding logs with query: {query}, limit: {limit}, offset: {offset}")
            
            cursor = self.collection.find(query).sort("timestamp", DESCENDING)
            
            if offset > 0:
                cursor = cursor.skip(offset)
            
            if limit and limit > 0:
                cursor = cursor.limit(limit)
            
            logs = list(cursor)
            
            self.logger.debug(f"Found {len(logs)} logs from database")
            
            # Convert ObjectId to string and handle timezone
            for log in logs:
                log["_id"] = str(log["_id"])
                
                # Convert timestamp to Vietnam timezone for display
                if "timestamp" in log and isinstance(log["timestamp"], datetime):
                    vn_time = self._ensure_vietnam_timezone(log["timestamp"])
                    log["timestamp"] = vn_time
                    log["display_time"] = vn_time.strftime('%H:%M:%S')
                
                # Ensure all required fields exist with defaults
                log.setdefault("level", "INFO")
                log.setdefault("action", "UNKNOWN")
                log.setdefault("domain", "unknown")
                log.setdefault("destination", "unknown")
                log.setdefault("source_ip", "unknown")
                log.setdefault("dest_ip", "unknown")
                log.setdefault("protocol", "unknown")
                log.setdefault("port", "unknown")
                log.setdefault("message", "Log entry")
                log.setdefault("agent_id", "unknown")
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Error finding logs: {e}")
            import traceback
            traceback.print_exc()
            return []

    def delete_logs(self, query: Dict = None) -> int:
        """Delete logs with optional query"""
        try:
            if query is None:
                query = {}
            
            result = self.collection.delete_many(query)
            deleted_count = result.deleted_count
            
            self.logger.info(f"Deleted {deleted_count} logs with query: {query}")
            return deleted_count
            
        except Exception as e:
            self.logger.error(f"Error deleting logs: {e}")
            return 0

    def insert_logs(self, logs: List[Dict]) -> List[str]:
        """Insert multiple log entries with Vietnam timezone"""
        if not logs:
            return []
        
        current_time = self._now_local()
        
        # ✅ FIX: Process timestamps for Vietnam timezone
        for log in logs:
            if 'timestamp' not in log:
                log['timestamp'] = current_time
            else:
                log['timestamp'] = self._parse_timestamp(log['timestamp'])
            
            # ✅ ADD: Server received timestamp
            log['server_received_at'] = current_time
        
        result = self.collection.insert_many(logs)
        self.logger.info(f"Inserted {len(logs)} logs with Vietnam timezone")
        return [str(id) for id in result.inserted_ids]
    
    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp and convert to Vietnam timezone"""
        if isinstance(timestamp, datetime):
            return self._ensure_vietnam_timezone(timestamp)
        elif isinstance(timestamp, str):
            try:
                # Parse ISO string
                dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                return self._ensure_vietnam_timezone(dt)
            except (ValueError, TypeError):
                self.logger.warning(f"Failed to parse timestamp '{timestamp}', using current time")
                return self._now_local()
        else:
            self.logger.warning(f"Invalid timestamp type: {type(timestamp)}, using current time")
            return self._now_local()
    
    def get_total_count(self) -> int:
        """Get total count of all logs"""
        try:
            return self.collection.count_documents({})
        except Exception as e:
            self.logger.error(f"Error getting total count: {e}")
            return 0
    
    def get_count_by_action(self, action: str) -> int:
        """Get count of logs by action"""
        try:
            return self.collection.count_documents({'action': action})
        except Exception as e:
            self.logger.error(f"Error getting count by action {action}: {e}")
            return 0
    
    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent logs in Vietnam timezone"""
        try:
            logs = list(self.collection.find()
                       .sort('timestamp', DESCENDING)
                       .limit(limit))
            
            # ✅ FIX: Convert to Vietnam timezone
            for log in logs:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                    vn_time = self._ensure_vietnam_timezone(log['timestamp'])
                    log['timestamp'] = vn_time.isoformat()
                    log['display_time'] = vn_time.strftime('%Y-%m-%d %H:%M:%S')
                    log['time_ago'] = self._get_time_ago(vn_time)
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Error getting recent logs: {e}")
            return []
    
    def _get_time_ago(self, timestamp: datetime) -> str:
        """Get human-readable time ago string"""
        now = self._now_local()
        diff = now - timestamp
        
        if diff.days > 0:
            return f"{diff.days} ngày trước"
        elif diff.seconds > 3600:
            hours = diff.seconds // 3600
            return f"{hours} giờ trước"
        elif diff.seconds > 60:
            minutes = diff.seconds // 60
            return f"{minutes} phút trước"
        else:
            return "Vừa xong"

    # Add other methods that were in the original file...
    def find_logs(self, query: Dict = None, limit: int = 100, skip: int = 0, 
                  sort_field: str = "timestamp", sort_order: int = DESCENDING) -> List[Dict]:
        """Find logs with query"""
        try:
            if query is None:
                query = {}
            
            logs = list(self.collection.find(query)
                       .sort(sort_field, sort_order)
                       .skip(skip)
                       .limit(limit))
            
            # ✅ FIX: Convert to Vietnam timezone
            for log in logs:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                    vn_time = self._ensure_vietnam_timezone(log['timestamp'])
                    log['timestamp'] = vn_time.isoformat()
                    log['display_time'] = vn_time.strftime('%Y-%m-%d %H:%M:%S')
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Error in find_logs: {e}")
            return []

    def get_logs_summary(self, since: datetime = None) -> Dict:
        """Get logs summary statistics since a date in Vietnam timezone"""
        try:
            if since is None:
                # Default to last 24 hours in Vietnam time
                since = self._now_local() - timedelta(days=1)
            else:
                # Ensure since is in Vietnam timezone
                since = self._ensure_vietnam_timezone(since)
            
            query = {'timestamp': {'$gte': since}}
            
            # Basic counts
            total_logs = self.collection.count_documents(query)
            allowed_logs = self.collection.count_documents({**query, 'action': 'ALLOWED'})
            blocked_logs = self.collection.count_documents({**query, 'action': 'BLOCKED'})
            error_logs = self.collection.count_documents({**query, 'level': 'ERROR'})
            
            return {
                'total_logs': total_logs,
                'allowed_logs': allowed_logs,
                'blocked_logs': blocked_logs,
                'error_logs': error_logs,
                'since': since.isoformat(),
                'timezone': 'UTC+7'
            }
            
        except Exception as e:
            self.logger.error(f"Error getting logs summary: {e}")
            return {
                'total_logs': 0,
                'allowed_logs': 0,
                'blocked_logs': 0,
                'error_logs': 0,
                'since': None,
                'timezone': 'UTC+7'
            }