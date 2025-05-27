"""
Log Service - Business logic for log operations
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from models.log_model import LogModel
import pytz  # ✅ ADD TIMEZONE SUPPORT

class LogService:
    """Service class for log business logic"""
    
    def __init__(self, log_model: LogModel, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = log_model
        self.socketio = socketio
        # ✅ ADD TIMEZONE
        self.timezone = pytz.timezone('Asia/Ho_Chi_Minh')  # Vietnam timezone
    
    def _get_current_time(self):
        """Get current time in configured timezone"""
        return datetime.now(self.timezone)
    
    def receive_logs(self, logs_data: Dict) -> Dict:
        """Process incoming logs from agents"""
        if not isinstance(logs_data, dict) or "logs" not in logs_data:
            raise ValueError("Invalid request format, 'logs' field required")
        
        logs = logs_data["logs"]
        if not isinstance(logs, list):
            raise ValueError("'logs' must be an array")
        
        # Validate and process each log
        valid_logs = []
        current_time = self._get_current_time()  # ✅ USE TIMEZONE-AWARE TIME
        
        for log in logs:
            if not isinstance(log, dict):
                continue
            
            # Ensure required fields exist
            if "domain" not in log or "agent_id" not in log:
                continue
            
            # ✅ HANDLE TIMEZONE-AWARE TIMESTAMPS
            if 'timestamp' not in log:
                log['timestamp'] = current_time
            else:
                # Parse and convert timestamp if needed
                timestamp_str = log['timestamp']
                if isinstance(timestamp_str, str):
                    try:
                        if timestamp_str.endswith('Z'):
                            parsed_time = datetime.fromisoformat(timestamp_str[:-1]).replace(tzinfo=pytz.UTC)
                        else:
                            parsed_time = datetime.fromisoformat(timestamp_str)
                            if parsed_time.tzinfo is None:
                                parsed_time = self.timezone.localize(parsed_time)
                        log['timestamp'] = parsed_time.astimezone(self.timezone)
                    except ValueError:
                        log['timestamp'] = current_time
            
            valid_logs.append(log)
        
        if not valid_logs:
            return {
                "status": "warning", 
                "message": "No valid logs provided",
                "count": 0
            }
        
        # Store logs in database using model
        inserted_ids = self.model.insert_logs(valid_logs)
        
        # Broadcast new logs via SocketIO
        if self.socketio:
            for log in valid_logs:
                log_copy = log.copy()
                if "timestamp" in log_copy and isinstance(log_copy["timestamp"], datetime):
                    log_copy["timestamp"] = log_copy["timestamp"].isoformat()
                self.socketio.emit('new_log', log_copy)
        
        self.logger.info(f"Processed {len(inserted_ids)} logs")
        
        return {
            "status": "success",
            "count": len(inserted_ids),
            "message": f"Processed {len(inserted_ids)} logs"
        }
    
    def get_logs(self, filters: Dict = None, limit: int = 100, skip: int = 0, 
                 sort_field: str = "timestamp", sort_order: str = "desc") -> Dict:
        """Get logs with filtering and pagination"""
        try:
            # Build query from filters
            query = {}
            if filters:
                query = self.model.build_query_from_filters(filters)
            
            # Determine sort order
            from pymongo import DESCENDING, ASCENDING
            mongo_sort_order = DESCENDING if sort_order.lower() == 'desc' else ASCENDING
            
            # Get logs from model
            logs = self.model.find_logs(
                query=query,
                limit=limit,
                skip=skip,
                sort_field=sort_field,
                sort_order=mongo_sort_order
            )
            
            # Get total count for pagination
            total_count = self.model.count_logs(query)
            
            return {
                "logs": logs,
                "total": total_count,
                "page": skip // limit + 1 if limit > 0 else 1,
                "pages": (total_count + limit - 1) // limit if limit > 0 else 1,
                "success": True
            }
            
        except Exception as e:
            self.logger.error(f"Error getting logs: {e}")
            return {
                "logs": [],
                "total": 0,
                "page": 1,
                "pages": 1,
                "success": False,
                "error": str(e)
            }
    
    def get_logs_summary(self, period: str = "day") -> Dict:
        """Get logs summary statistics"""
        try:
            # ✅ USE TIMEZONE-AWARE TIME CALCULATIONS
            now = self._get_current_time()
            if period == 'week':
                since = now - timedelta(days=7)
            elif period == 'month':
                since = now - timedelta(days=30)
            else:
                since = now - timedelta(days=1)
            
            # Get summary from model
            summary = self.model.get_logs_summary(since)
            
            # Add period info
            summary.update({
                "period": period,
                "since": since.isoformat(),
                "until": now.isoformat(),
                "success": True
            })
            
            return summary
            
        except Exception as e:
            self.logger.error(f"Error getting logs summary: {e}")
            return {
                "total_logs": 0,
                "allowed_logs": 0,
                "blocked_logs": 0,
                "error_logs": 0,
                "top_domains": [],
                "top_agents": [],
                "period": period,
                "success": False,
                "error": str(e)
            }
    
    def clear_logs(self, clear_data: Dict) -> Dict:
        """Clear logs by criteria"""
        try:
            # Build filters for clearing
            filters = {}
            
            if clear_data.get('clear_all'):
                # Clear all logs
                deleted_count = self.model.clear_logs()
            elif clear_data.get('filters'):
                # Clear with specific filters
                filters = clear_data['filters']
                deleted_count = self.model.clear_logs(filters)
            elif clear_data.get('older_than_days'):
                # ✅ TIMEZONE-AWARE DATE CALCULATION
                days = int(clear_data['older_than_days'])
                cutoff_date = self._get_current_time() - timedelta(days=days)
                filters = {'until': cutoff_date.isoformat()}
                deleted_count = self.model.clear_logs(filters)
            else:
                raise ValueError("No clear criteria specified")
            
            # ✅ USE TIMEZONE-AWARE TIMESTAMP
            current_time = self._get_current_time()
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit('logs_cleared', {
                    'deleted_count': deleted_count,
                    'timestamp': current_time.isoformat()
                })
            
            self.logger.info(f"Cleared {deleted_count} logs")
            
            return {
                "success": True,
                "deleted_count": deleted_count,
                "message": f"Cleared {deleted_count} logs"
            }
            
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            return {
                "success": False,
                "deleted_count": 0,
                "error": str(e),
                "message": "Failed to clear logs"
            }
    
    def get_all_logs(self, filters: Dict = None, page: int = 1, per_page: int = 50) -> Dict:
        """Get all logs with pagination"""
        try:
            return self.model.get_logs(filters, page, per_page)
        except Exception as e:
            self.logger.error(f"Error getting all logs: {e}")
            return {"error": str(e), "logs": [], "total": 0}
    
    def get_log_by_id(self, log_id: str) -> Dict:
        """Get single log by ID"""
        try:
            log = self.model.get_log_by_id(log_id)
            if log:
                return log
            return {"error": "Log not found"}
        except Exception as e:
            self.logger.error(f"Error getting log {log_id}: {e}")
            return {"error": str(e)}
    
    def delete_log(self, log_id: str) -> bool:
        """Delete a log entry"""
        try:
            result = self.model.delete_log(log_id)
            if result:
                # Emit real-time update if socketio is available
                if self.socketio:
                    self.socketio.emit('log_deleted', {'log_id': log_id})
                
                self.logger.info(f"Deleted log {log_id}")
                return True
            else:
                self.logger.warning(f"Log {log_id} not found for deletion")
                return False
        except Exception as e:
            self.logger.error(f"Error deleting log {log_id}: {e}")
            return False
    
    def add_log(self, log_data: Dict) -> Dict:
        """Add a new log entry"""
        try:
            log_id = self.model.insert_log(log_data)
            
            # Emit real-time update if socketio is available
            if self.socketio:
                log_data_copy = log_data.copy()
                log_data_copy['_id'] = log_id
                if 'timestamp' in log_data_copy and isinstance(log_data_copy['timestamp'], datetime):
                    log_data_copy['timestamp'] = log_data_copy['timestamp'].isoformat()
                self.socketio.emit('new_log', log_data_copy)
            
            self.logger.info(f"Added new log: {log_id}")
            
            return {"success": True, "log_id": log_id}
        except Exception as e:
            self.logger.error(f"Error adding log: {e}")
            return {"error": str(e)}
    
    # ✅ Methods for dashboard statistics
    def get_total_count(self) -> int:
        """Get total count of logs"""
        try:
            return self.model.get_total_count()
        except Exception as e:
            self.logger.error(f"Error getting total count: {e}")
            return 0
    
    def get_count_by_action(self, action: str) -> int:
        """Get count of logs by action (allow/block)"""
        try:
            return self.model.get_count_by_action(action)
        except Exception as e:
            self.logger.error(f"Error getting count by action {action}: {e}")
            return 0
    
    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent logs for dashboard"""
        try:
            return self.model.get_recent_logs(limit)
        except Exception as e:
            self.logger.error(f"Error getting recent logs: {e}")
            return []