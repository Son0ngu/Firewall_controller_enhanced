"""
Log Model - handles log data operations
"""

from datetime import datetime, timedelta, timezone
# ✅ FIXED: Remove ZoneInfo import (Windows compatibility)
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
        
        # ✅ FIXED: Force UTC+7 timezone for Vietnam
        self.vietnam_timezone = timezone(timedelta(hours=7), name="UTC+7")
        self._create_indexes()
        
        logger.info(f"LogModel initialized with Vietnam timezone: {self.vietnam_timezone}")
    
    def _get_vietnam_timezone(self) -> timezone:
        """Get Vietnam timezone (UTC+7)"""
        return timezone(timedelta(hours=7), name="UTC+7")
    
    def _now_local(self) -> datetime:
        """Get current time in Vietnam timezone"""
        # ✅ FIX: Always get UTC time first, then convert to Vietnam
        utc_now = datetime.now(timezone.utc)
        vn_time = utc_now.astimezone(self.vietnam_timezone)
        
        # ✅ DEBUG: Log time calculation
        logger.debug(f"UTC time: {utc_now.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        logger.debug(f"VN time:  {vn_time.strftime('%Y-%m-%d %H:%M:%S %Z')}")
        
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
            
            logger.info("Log indexes created successfully")
            
        except Exception as e:
            logger.warning(f"Could not create log indexes: {e}")
    
    def get_logs(self, filters: Dict = None, page: int = 1, per_page: int = 50) -> Dict:
        """Get logs with filtering and pagination"""
        query = {}
        
        if filters:
            if filters.get('agent_id'):
                query['agent_id'] = filters['agent_id']
            
            if filters.get('action'):
                query['action'] = filters['action']
            
            if filters.get('domain'):
                query['domain'] = {'$regex': filters['domain'], '$options': 'i'}
            
            if filters.get('start_date') and filters.get('end_date'):
                # ✅ FIX: Ensure dates are in Vietnam timezone
                start_date = self._parse_date_string(filters['start_date'])
                end_date = self._parse_date_string(filters['end_date'])
                
                if start_date and end_date:
                    query['timestamp'] = {
                        '$gte': start_date,
                        '$lte': end_date
                    }
        
        # Get total count
        total = self.collection.count_documents(query)
        
        # Get paginated results
        skip = (page - 1) * per_page
        logs = list(self.collection.find(query)
                   .sort('timestamp', DESCENDING)
                   .skip(skip)
                   .limit(per_page))
        
        # ✅ FIX: Convert to Vietnam timezone and format
        for log in logs:
            log['_id'] = str(log['_id'])
            if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                # Convert to Vietnam timezone
                vn_time = self._ensure_vietnam_timezone(log['timestamp'])
                log['timestamp'] = vn_time.isoformat()
                log['display_time'] = vn_time.strftime('%Y-%m-%d %H:%M:%S')
            
            # ✅ ADD: Server received timestamp
            if 'server_received_at' in log and isinstance(log['server_received_at'], datetime):
                vn_received = self._ensure_vietnam_timezone(log['server_received_at'])
                log['server_received_at'] = vn_received.isoformat()
        
        return {
            'logs': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page,
            'timezone': 'UTC+7'
        }
    
    def _parse_date_string(self, date_str: str) -> datetime:
        """Parse date string and convert to Vietnam timezone"""
        try:
            # Parse ISO format
            if 'T' in date_str:
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            else:
                # Parse date only format (assume start of day in Vietnam)
                dt = datetime.strptime(date_str, '%Y-%m-%d')
                dt = dt.replace(tzinfo=self.vietnam_timezone)
            
            return self._ensure_vietnam_timezone(dt)
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse date string '{date_str}': {e}")
            return None
    
    def get_log_by_id(self, log_id: str) -> Dict:
        """Get single log by ID"""
        try:
            log = self.collection.find_one({'_id': ObjectId(log_id)})
            if log:
                log['_id'] = str(log['_id'])
                
                # ✅ FIX: Convert timestamps to Vietnam timezone
                if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                    vn_time = self._ensure_vietnam_timezone(log['timestamp'])
                    log['timestamp'] = vn_time.isoformat()
                    log['display_time'] = vn_time.strftime('%Y-%m-%d %H:%M:%S')
                
                if 'server_received_at' in log and isinstance(log['server_received_at'], datetime):
                    vn_received = self._ensure_vietnam_timezone(log['server_received_at'])
                    log['server_received_at'] = vn_received.isoformat()
                
            return log
        except Exception as e:
            logger.error(f"Error getting log by ID {log_id}: {e}")
            return None
    
    def insert_log(self, log_data: Dict) -> str:
        """Insert new log entry with Vietnam timezone"""
        # ✅ FIX: Use Vietnam time if no timestamp provided
        if 'timestamp' not in log_data:
            log_data['timestamp'] = self._now_local()
        else:
            # Parse and convert existing timestamp to Vietnam timezone
            log_data['timestamp'] = self._parse_timestamp(log_data['timestamp'])
        
        # ✅ ADD: Server received timestamp
        log_data['server_received_at'] = self._now_local()
        
        result = self.collection.insert_one(log_data)
        return str(result.inserted_id)
    
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
        logger.info(f"Inserted {len(logs)} logs with Vietnam timezone")
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
                logger.warning(f"Failed to parse timestamp '{timestamp}', using current time")
                return self._now_local()
        else:
            logger.warning(f"Invalid timestamp type: {type(timestamp)}, using current time")
            return self._now_local()
    
    def delete_log(self, log_id: str) -> bool:
        """Delete log entry"""
        try:
            result = self.collection.delete_one({'_id': ObjectId(log_id)})
            return result.deleted_count > 0
        except Exception as e:
            logger.error(f"Error deleting log {log_id}: {e}")
            return False
    
    def clear_logs(self, filters: Dict = None) -> int:
        """Clear logs with optional filters"""
        query = {}
        if filters:
            query = self.build_query_from_filters(filters)
        
        result = self.collection.delete_many(query)
        logger.info(f"Cleared {result.deleted_count} logs")
        return result.deleted_count
    
    def build_query_from_filters(self, filters: Dict) -> Dict:
        """Build MongoDB query from filters with Vietnam timezone support"""
        query = {}
        
        if filters.get('agent_id'):
            query['agent_id'] = filters['agent_id']
        
        if filters.get('action'):
            query['action'] = filters['action']
        
        if filters.get('domain'):
            query['domain'] = {'$regex': filters['domain'], '$options': 'i'}
        
        if filters.get('level'):
            query['level'] = filters['level']
        
        # ✅ FIX: Date range filtering with Vietnam timezone
        if filters.get('since') or filters.get('until'):
            date_query = {}
            
            if filters.get('since'):
                since_date = self._parse_date_string(filters['since'])
                if since_date:
                    date_query['$gte'] = since_date
            
            if filters.get('until'):
                until_date = self._parse_date_string(filters['until'])
                if until_date:
                    date_query['$lte'] = until_date
            
            if date_query:
                query['timestamp'] = date_query
        
        return query
    
    def find_logs(self, query: Dict = None, limit: int = 100, skip: int = 0, 
                  sort_field: str = "timestamp", sort_order: int = DESCENDING) -> List[Dict]:
        """Find logs with query"""
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
    
    def count_logs(self, query: Dict = None) -> int:
        """Count logs matching query"""
        if query is None:
            query = {}
        return self.collection.count_documents(query)
    
    def get_logs_summary(self, since: datetime = None) -> Dict:
        """Get logs summary statistics since a date in Vietnam timezone"""
        if since is None:
            # Default to last 24 hours in Vietnam time
            since = self._now_local() - timedelta(days=1)
        else:
            # Ensure since is in Vietnam timezone
            since = self._ensure_vietnam_timezone(since)
        
        query = {'timestamp': {'$gte': since}}
        
        # Basic counts
        total_logs = self.collection.count_documents(query)
        allowed_logs = self.collection.count_documents({**query, 'action': 'allow'})
        blocked_logs = self.collection.count_documents({**query, 'action': 'block'})
        error_logs = self.collection.count_documents({**query, 'level': 'error'})
        
        # Top domains
        pipeline = [
            {'$match': query},
            {'$group': {'_id': '$domain', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        
        top_domains = list(self.collection.aggregate(pipeline))
        
        # Top agents
        pipeline = [
            {'$match': query},
            {'$group': {'_id': '$agent_id', 'count': {'$sum': 1}}},
            {'$sort': {'count': -1}},
            {'$limit': 10}
        ]
        
        top_agents = list(self.collection.aggregate(pipeline))
        
        return {
            'total_logs': total_logs,
            'allowed_logs': allowed_logs,
            'blocked_logs': blocked_logs,
            'error_logs': error_logs,
            'top_domains': top_domains,
            'top_agents': top_agents,
            'since': since.isoformat(),
            'timezone': 'UTC+7'
        }
    
    # Statistics methods for dashboard
    def get_total_count(self) -> int:
        """Get total count of all logs"""
        return self.collection.count_documents({})
    
    def get_count_by_action(self, action: str) -> int:
        """Get count of logs by action"""
        return self.collection.count_documents({'action': action})
    
    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent logs in Vietnam timezone"""
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
    
    def get_hourly_stats(self, hours: int = 24) -> List[Dict]:
        """Get hourly log statistics for the last N hours"""
        end_time = self._now_local()
        start_time = end_time - timedelta(hours=hours)
        
        pipeline = [
            {
                '$match': {
                    'timestamp': {'$gte': start_time, '$lte': end_time}
                }
            },
            {
                '$group': {
                    '_id': {
                        'year': {'$year': '$timestamp'},
                        'month': {'$month': '$timestamp'}, 
                        'day': {'$dayOfMonth': '$timestamp'},
                        'hour': {'$hour': '$timestamp'}
                    },
                    'count': {'$sum': 1},
                    'allowed': {
                        '$sum': {'$cond': [{'$eq': ['$action', 'allow']}, 1, 0]}
                    },
                    'blocked': {
                        '$sum': {'$cond': [{'$eq': ['$action', 'block']}, 1, 0]}
                    }
                }
            },
            {
                '$sort': {'_id': 1}
            }
        ]
        
        results = list(self.collection.aggregate(pipeline))
        
        # Format results
        formatted_results = []
        for result in results:
            dt = datetime(
                result['_id']['year'],
                result['_id']['month'], 
                result['_id']['day'],
                result['_id']['hour'],
                tzinfo=self.vietnam_timezone
            )
            
            formatted_results.append({
                'timestamp': dt.isoformat(),
                'hour_label': dt.strftime('%H:00'),
                'date_label': dt.strftime('%m/%d %H:00'),
                'total': result['count'],
                'allowed': result['allowed'],
                'blocked': result['blocked']
            })
        
        return formatted_results