"""
Log Model - handles log data operations
UTC ONLY - Clean and simple
"""

from typing import Dict, List, Optional
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
import logging

# Import time utilities - UTC ONLY
from time_utils import (
    now_utc, to_utc_naive, parse_agent_timestamp, 
    get_time_ago_string, calculate_age_seconds, format_datetime
)

logger = logging.getLogger(__name__)

class LogModel:
    """Model for log data operations - UTC ONLY"""
    
    def __init__(self, db: Database):
        self.db = db
        self.collection: Collection = db.logs
        self.logger = logging.getLogger(self.__class__.__name__)
        self._create_indexes()
        
        self.logger.info("LogModel initialized with UTC timezone support")
    
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
        """Find all logs with enhanced debugging - UTC ONLY"""
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
            
            # Convert ObjectId to string and handle timezone - UTC ONLY
            for log in logs:
                log["_id"] = str(log["_id"])
                
                # Convert timestamp to UTC for display
                if "timestamp" in log and log["timestamp"]:
                    if isinstance(log["timestamp"], str):
                        utc_time = parse_agent_timestamp(log["timestamp"])  # UTC parsing
                    else:
                        # Convert to UTC
                        from datetime import datetime, timezone
                        if isinstance(log["timestamp"], datetime):
                            if log["timestamp"].tzinfo is None:
                                utc_time = log["timestamp"].replace(tzinfo=timezone.utc)
                            else:
                                utc_time = log["timestamp"].astimezone(timezone.utc)
                        else:
                            utc_time = now_utc()
                    
                    log["timestamp"] = utc_time
                    log["display_time"] = utc_time.strftime('%H:%M:%S')
                
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
        """Insert multiple log entries with UTC timezone"""
        if not logs:
            return []
        
        current_time = to_utc_naive(now_utc())  # UTC naive for MongoDB
        
        # Process timestamps for UTC timezone
        for log in logs:
            if 'timestamp' not in log:
                log['timestamp'] = current_time
            else:
                log['timestamp'] = self._parse_timestamp(log['timestamp'])
            
            # Add server received timestamp - UTC
            log['server_received_at'] = current_time
        
        result = self.collection.insert_many(logs)
        self.logger.info(f"Inserted {len(logs)} logs with UTC timezone")
        return [str(id) for id in result.inserted_ids]
    
    def _parse_timestamp(self, timestamp) -> object:
        """Parse timestamp and convert to UTC naive datetime"""
        if timestamp is None:
            return to_utc_naive(now_utc())
        
        try:
            if isinstance(timestamp, str):
                # Parse ISO string and convert to UTC naive
                utc_time = parse_agent_timestamp(timestamp)  # UTC parsing
                return utc_time.replace(tzinfo=None)
            else:
                # Convert datetime to UTC naive
                from datetime import datetime, timezone
                if isinstance(timestamp, datetime):
                    if timestamp.tzinfo is None:
                        utc_time = timestamp.replace(tzinfo=timezone.utc)
                    else:
                        utc_time = timestamp.astimezone(timezone.utc)
                    return utc_time.replace(tzinfo=None)
                else:
                    return to_utc_naive(now_utc())
        except Exception as e:
            self.logger.warning(f"Failed to parse timestamp '{timestamp}': {e}, using current time")
            return to_utc_naive(now_utc())
    
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
        """Get recent logs in UTC timezone"""
        try:
            logs = list(self.collection.find()
                       .sort('timestamp', DESCENDING)
                       .limit(limit))
            
            # Convert to UTC timezone
            for log in logs:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log and log['timestamp']:
                    if isinstance(log['timestamp'], str):
                        utc_time = parse_agent_timestamp(log['timestamp'])  # UTC parsing
                    else:
                        # Convert to UTC
                        from datetime import datetime, timezone
                        if isinstance(log['timestamp'], datetime):
                            if log['timestamp'].tzinfo is None:
                                utc_time = log['timestamp'].replace(tzinfo=timezone.utc)
                            else:
                                utc_time = log['timestamp'].astimezone(timezone.utc)
                        else:
                            utc_time = now_utc()
                    
                    log['timestamp'] = utc_time.isoformat()
                    log['display_time'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
                    log['time_ago'] = get_time_ago_string(utc_time)
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Error getting recent logs: {e}")
            return []
    
    def find_logs(self, query: Dict = None, limit: int = 100, skip: int = 0, 
                  sort_field: str = "timestamp", sort_order: int = DESCENDING) -> List[Dict]:
        """Find logs with query - UTC ONLY"""
        try:
            if query is None:
                query = {}
            
            logs = list(self.collection.find(query)
                       .sort(sort_field, sort_order)
                       .skip(skip)
                       .limit(limit))
            
            # Convert to UTC timezone
            for log in logs:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log and log['timestamp']:
                    if isinstance(log['timestamp'], str):
                        utc_time = parse_agent_timestamp(log['timestamp'])  # UTC parsing
                    else:
                        # Convert to UTC
                        from datetime import datetime, timezone
                        if isinstance(log['timestamp'], datetime):
                            if log['timestamp'].tzinfo is None:
                                utc_time = log['timestamp'].replace(tzinfo=timezone.utc)
                            else:
                                utc_time = log['timestamp'].astimezone(timezone.utc)
                        else:
                            utc_time = now_utc()
                    
                    log['timestamp'] = utc_time.isoformat()
                    log['display_time'] = utc_time.strftime('%Y-%m-%d %H:%M:%S')
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Error in find_logs: {e}")
            return []

    def get_logs_summary(self, since: object = None) -> Dict:
        """Get logs summary statistics since a date in UTC timezone"""
        try:
            if since is None:
                # Default to last 24 hours in UTC time
                from datetime import timedelta
                since = to_utc_naive(now_utc()) - timedelta(days=1)
            else:
                # Convert to UTC naive for MongoDB query
                if isinstance(since, str):
                    since_utc = parse_agent_timestamp(since)  # UTC parsing
                else:
                    from datetime import datetime, timezone
                    if isinstance(since, datetime):
                        if since.tzinfo is None:
                            since_utc = since.replace(tzinfo=timezone.utc)
                        else:
                            since_utc = since.astimezone(timezone.utc)
                    else:
                        since_utc = now_utc()
                since = since_utc.replace(tzinfo=None)
            
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
                'since': since.isoformat() if hasattr(since, 'isoformat') else str(since),
                'timezone': 'UTC'  # Changed from 'UTC+7'
            }
            
        except Exception as e:
            self.logger.error(f"Error getting logs summary: {e}")
            return {
                'total_logs': 0,
                'allowed_logs': 0,
                'blocked_logs': 0,
                'error_logs': 0,
                'since': None,
                'timezone': 'UTC'  # Changed from 'UTC+7'
            }