"""
Log Model - handles log data operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional
from bson import ObjectId
from pymongo import ASCENDING, DESCENDING
from pymongo.collection import Collection
from pymongo.database import Database
import pytz  # ✅ ADD TIMEZONE SUPPORT

class LogModel:
    """Model for log data operations"""
    
    def __init__(self, db: Database):
        self.db = db
        self.collection: Collection = db.logs
        # ✅ ADD TIMEZONE
        self.timezone = pytz.timezone('Asia/Ho_Chi_Minh')  # Vietnam timezone
        self._create_indexes()
    
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
            
        except Exception as e:
            print(f"Warning: Could not create indexes: {e}")
    
    def _get_current_time(self):
        """Get current time in configured timezone"""
        return datetime.now(self.timezone)
    
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
                query['timestamp'] = {
                    '$gte': filters['start_date'],
                    '$lte': filters['end_date']
                }
        
        # Get total count
        total = self.collection.count_documents(query)
        
        # Get paginated results
        skip = (page - 1) * per_page
        logs = list(self.collection.find(query)
                   .sort('timestamp', DESCENDING)
                   .skip(skip)
                   .limit(per_page))
        
        # Convert ObjectId to string and datetime to ISO string
        for log in logs:
            log['_id'] = str(log['_id'])
            if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                log['timestamp'] = log['timestamp'].isoformat()
        
        return {
            'logs': logs,
            'total': total,
            'page': page,
            'per_page': per_page,
            'pages': (total + per_page - 1) // per_page
        }
    
    def get_log_by_id(self, log_id: str) -> Dict:
        """Get single log by ID"""
        try:
            log = self.collection.find_one({'_id': ObjectId(log_id)})
            if log:
                log['_id'] = str(log['_id'])
                if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                    log['timestamp'] = log['timestamp'].isoformat()
            return log
        except Exception:
            return None
    
    def insert_log(self, log_data: Dict) -> str:
        """Insert new log entry"""
        # ✅ USE TIMEZONE-AWARE TIME
        if 'timestamp' not in log_data:
            log_data['timestamp'] = self._get_current_time()
        result = self.collection.insert_one(log_data)
        return str(result.inserted_id)
    
    def insert_logs(self, logs: List[Dict]) -> List[str]:
        """Insert multiple log entries"""
        if not logs:
            return []
        
        # ✅ USE TIMEZONE-AWARE TIME
        current_time = self._get_current_time()
        
        # Add timestamp to logs that don't have one
        for log in logs:
            if 'timestamp' not in log:
                log['timestamp'] = current_time
        
        result = self.collection.insert_many(logs)
        return [str(id) for id in result.inserted_ids]
    
    def delete_log(self, log_id: str) -> bool:
        """Delete log entry"""
        try:
            result = self.collection.delete_one({'_id': ObjectId(log_id)})
            return result.deleted_count > 0
        except Exception:
            return False
    
    def clear_logs(self, filters: Dict = None) -> int:
        """Clear logs with optional filters"""
        query = {}
        if filters:
            query = self.build_query_from_filters(filters)
        
        result = self.collection.delete_many(query)
        return result.deleted_count
    
    def build_query_from_filters(self, filters: Dict) -> Dict:
        """Build MongoDB query from filters"""
        query = {}
        
        if filters.get('agent_id'):
            query['agent_id'] = filters['agent_id']
        
        if filters.get('action'):
            query['action'] = filters['action']
        
        if filters.get('domain'):
            query['domain'] = {'$regex': filters['domain'], '$options': 'i'}
        
        if filters.get('level'):
            query['level'] = filters['level']
        
        # ✅ TIMEZONE-AWARE DATE RANGE FILTERING
        if filters.get('since') or filters.get('until'):
            date_query = {}
            if filters.get('since'):
                try:
                    since_str = filters['since']
                    if since_str.endswith('Z'):
                        since_date = datetime.fromisoformat(since_str[:-1]).replace(tzinfo=pytz.UTC)
                    else:
                        since_date = datetime.fromisoformat(since_str)
                        if since_date.tzinfo is None:
                            since_date = self.timezone.localize(since_date)
                    date_query['$gte'] = since_date.astimezone(self.timezone)
                except:
                    pass
            
            if filters.get('until'):
                try:
                    until_str = filters['until']
                    if until_str.endswith('Z'):
                        until_date = datetime.fromisoformat(until_str[:-1]).replace(tzinfo=pytz.UTC)
                    else:
                        until_date = datetime.fromisoformat(until_str)
                        if until_date.tzinfo is None:
                            until_date = self.timezone.localize(until_date)
                    date_query['$lte'] = until_date.astimezone(self.timezone)
                except:
                    pass
            
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
        
        # Convert ObjectId to string and datetime to ISO string
        for log in logs:
            log['_id'] = str(log['_id'])
            if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                log['timestamp'] = log['timestamp'].isoformat()
        
        return logs
    
    def count_logs(self, query: Dict = None) -> int:
        """Count logs matching query"""
        if query is None:
            query = {}
        return self.collection.count_documents(query)
    
    def get_logs_summary(self, since: datetime) -> Dict:
        """Get logs summary statistics since a date"""
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
            'top_agents': top_agents
        }
    
    # ✅ Statistics methods for dashboard
    def get_total_count(self) -> int:
        """Get total count of all logs"""
        return self.collection.count_documents({})
    
    def get_count_by_action(self, action: str) -> int:
        """Get count of logs by action"""
        return self.collection.count_documents({'action': action})
    
    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent logs"""
        logs = list(self.collection.find()
                   .sort('timestamp', DESCENDING)
                   .limit(limit))
        
        # Convert ObjectId to string and datetime to ISO string
        for log in logs:
            log['_id'] = str(log['_id'])
            if 'timestamp' in log and isinstance(log['timestamp'], datetime):
                log['timestamp'] = log['timestamp'].isoformat()
        
        return logs