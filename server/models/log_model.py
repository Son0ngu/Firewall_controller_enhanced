"""
Log Model - handles log data operations
vietnam ONLY - Clean and simple
"""

from typing import Dict, List, Optional
from datetime import datetime
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
import logging

# Import time utilities - vietnam ONLY
from time_utils import (
    now_vietnam,
    to_vietnam,
    parse_agent_timestamp,
    get_time_ago_string,
    format_datetime,
)

logger = logging.getLogger(__name__)

class LogModel:
    """Model for log data operations - vietnam ONLY"""
    
    def __init__(self, db: Database):
        self.db = db
        self.collection: Collection = db.logs
        self.logger = logging.getLogger(self.__class__.__name__)
        self._create_indexes()
        
        self.logger.info("LogModel initialized with vietnam timezone support")
    
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
        """Find all logs with enhanced debugging - vietnam ONLY"""
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
            
            # Convert ObjectId to string and handle timezone - vietnam ONLY
            for log in logs:
                log["_id"] = str(log["_id"])
                
                # Convert timestamp to vietnam for display
                if "timestamp" in log and log["timestamp"]:
                    if isinstance(log["timestamp"], str):
                        vietnam_time = parse_agent_timestamp(log["timestamp"])  # vietnam parsing
                    elif isinstance(log["timestamp"], datetime):
                        vietnam_time = to_vietnam(log["timestamp"])
                    else:
                        vietnam_time = now_vietnam()
                    
                    log["timestamp"] = vietnam_time
                    log["display_time"] = vietnam_time.strftime('%H:%M:%S')
                
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
        """Insert multiple log entries with vietnam timezone"""
        if not logs:
            return []
        
        current_time = now_vietnam()
        
        # Process timestamps for vietnam timezone
        for log in logs:
            if 'timestamp' not in log:
                log['timestamp'] = current_time
            else:
                log['timestamp'] = self._parse_timestamp(log['timestamp'])
            
            # Add server received timestamp - vietnam
            log['server_received_at'] = current_time
        
        result = self.collection.insert_many(logs)
        self.logger.info(f"Inserted {len(logs)} logs with vietnam timezone")
        return [str(id) for id in result.inserted_ids]
    
    def _parse_timestamp(self, timestamp) -> datetime:
        """Parse timestamp and convert to Vietnam aware datetime."""
        if timestamp is None:
            return now_vietnam()
        
        try:
            return parse_agent_timestamp(timestamp)
        except Exception as e:
            self.logger.warning(f"Failed to parse timestamp '{timestamp}': {e}, using current time")
            return now_vietnam()
    
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
        """Get recent logs in vietnam timezone"""
        try:
            logs = list(self.collection.find()
                       .sort('timestamp', DESCENDING)
                       .limit(limit))
            
            # Convert to vietnam timezone
            for log in logs:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log and log['timestamp']:
                    if isinstance(log['timestamp'], str):
                        vietnam_time = parse_agent_timestamp(log['timestamp'])  # vietnam parsing
                    elif isinstance(log['timestamp'], datetime):
                        vietnam_time = to_vietnam(log['timestamp'])   
                    else:
                        vietnam_time = now_vietnam()
                    
                    log['timestamp'] = vietnam_time.isoformat()
                    log['display_time'] = vietnam_time.strftime('%Y-%m-%d %H:%M:%S')
                    log['time_ago'] = get_time_ago_string(vietnam_time)
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Error getting recent logs: {e}")
            return []
    
    def find_logs(self, query: Dict = None, limit: int = 100, skip: int = 0, 
                  sort_field: str = "timestamp", sort_order: int = DESCENDING) -> List[Dict]:
        """Find logs with query - vietnam ONLY"""
        try:
            if query is None:
                query = {}
            
            logs = list(self.collection.find(query)
                       .sort(sort_field, sort_order)
                       .skip(skip)
                       .limit(limit))
            
            # Convert to vietnam timezone
            for log in logs:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log and log['timestamp']:
                    if isinstance(log['timestamp'], str):
                        vietnam_time = parse_agent_timestamp(log['timestamp'])  # vietnam parsing
                    elif isinstance(log['timestamp'], datetime):
                        vietnam_time = to_vietnam(log['timestamp'])
                    else:
                         vietnam_time = now_vietnam()
                    
                    log['timestamp'] = vietnam_time.isoformat()
                    log['display_time'] = vietnam_time.strftime('%Y-%m-%d %H:%M:%S')
            
            return logs
            
        except Exception as e:
            self.logger.error(f"Error in find_logs: {e}")
            return []

    def get_logs_summary(self, since: object = None) -> Dict:
        """Get logs summary statistics since a date in vietnam timezone"""
        try:
            if since is None:
                from datetime import timedelta
                since_dt = now_vietnam() - timedelta(days=1)
            else:
                since_dt = parse_agent_timestamp(since)

            query = {'timestamp': {'$gte': since_dt}}
            
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
                'since': since_dt.isoformat(),
                'timezone': 'vietnam'  # Changed from 'vietnam+7'
            }
            
        except Exception as e:
            self.logger.error(f"Error getting logs summary: {e}")
            return {
                'total_logs': 0,
                'allowed_logs': 0,
                'blocked_logs': 0,
                'error_logs': 0,
                'since': None,
                'timezone': 'vietnam'  # Changed from 'vietnam+7'
            }