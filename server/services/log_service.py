"""
Log Service - Business logic for log operations
"""
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from models.log_model import LogModel
import logging

logger = logging.getLogger(__name__)

class LogService:
    """Service class for log business logic"""
    
    def __init__(self, log_model: LogModel, socketio=None):
        self.model = log_model
        self.socketio = socketio
        
        # ✅ FIX: Use Vietnam timezone consistently
        self.vietnam_timezone = timezone(timedelta(hours=7), name="UTC+7")
        
        logger.info(f"LogService initialized with Vietnam timezone: {self.vietnam_timezone}")
    
    def _now_local(self) -> datetime:
        """Get current time in Vietnam timezone"""
        utc_now = datetime.now(timezone.utc)
        return utc_now.astimezone(self.vietnam_timezone)
    
    def _ensure_vietnam_timezone(self, dt: datetime) -> datetime:
        """Ensure datetime is in Vietnam timezone"""
        if dt is None:
            return None
            
        if dt.tzinfo is None:
            # Naive datetime - assume it's Vietnam time
            return dt.replace(tzinfo=self.vietnam_timezone)
        else:
            # Convert to Vietnam timezone
            return dt.astimezone(self.vietnam_timezone)
    
    def receive_logs(self, logs_data: Dict, agent_id: str = None) -> Dict:
        """Process logs received from agent"""
        try:
            logs = logs_data.get("logs", [])
            if not logs:
                return {"success": False, "error": "No logs provided"}
            
            current_time = self._now_local()
            
            valid_logs = []
            for log in logs:
                try:
                    # ✅ FIX: Timestamp processing for Vietnam timezone
                    if 'timestamp' not in log:
                        # No timestamp from agent -> use server time
                        log['timestamp'] = current_time
                        log['timestamp_source'] = 'server'
                    else:
                        try:
                            # Parse agent timestamp
                            if isinstance(log['timestamp'], str):
                                agent_time = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                            else:
                                agent_time = log['timestamp']
                            
                            # Convert to Vietnam timezone
                            log['timestamp'] = self._ensure_vietnam_timezone(agent_time)
                            log['timestamp_source'] = 'agent'
                            
                        except (ValueError, TypeError) as e:
                            logger.warning(f"Invalid timestamp format '{log.get('timestamp')}': {e}")
                            log['timestamp'] = current_time
                            log['timestamp_source'] = 'server_fallback'
                    
                    # ✅ ADD: Server received timestamp in Vietnam timezone
                    log['server_received_at'] = current_time
                    
                    # ✅ ADD: Agent info
                    if agent_id:
                        log['agent_id'] = agent_id
                    
                    # ✅ FIX: Normalize fields
                    if 'url' in log and 'domain' not in log:
                        log['domain'] = log['url']
                    
                    if 'action' not in log:
                        log['action'] = 'unknown'
                    
                    # ✅ ADD: Log level
                    if 'level' not in log:
                        log['level'] = 'info'
                    
                    valid_logs.append(log)
                    
                except Exception as e:
                    logger.warning(f"Error processing log entry: {e}")
                    continue
            
            if not valid_logs:
                return {"success": False, "error": "No valid logs to process"}
            
            # Store in database
            inserted_ids = self.model.insert_logs(valid_logs)
            
            # ✅ Real-time broadcast via Socket.IO
            if self.socketio:
                for log in valid_logs[-5:]:  # Broadcast last 5 logs to avoid flooding
                    # Format for frontend
                    broadcast_log = {
                        'timestamp': log['timestamp'].isoformat() if isinstance(log['timestamp'], datetime) else log['timestamp'],
                        'display_time': log['timestamp'].strftime('%H:%M:%S') if isinstance(log['timestamp'], datetime) else log['timestamp'],
                        'domain': log.get('domain', 'Unknown'),
                        'action': log.get('action', 'unknown'),
                        'agent_id': log.get('agent_id', 'Unknown'),
                        'level': log.get('level', 'info')
                    }
                    self.socketio.emit('new_log', broadcast_log)
            
            logger.info(f"Successfully processed {len(valid_logs)} logs from agent {agent_id}")
            
            return {
                "success": True,
                "message": f"Successfully processed {len(valid_logs)} logs",
                "inserted_ids": inserted_ids,
                "processed_count": len(valid_logs),
                "timestamp": current_time.isoformat(),
                "timezone": "UTC+7"
            }
            
        except Exception as e:
            logger.error(f"Error receiving logs: {e}")
            return {"success": False, "error": str(e)}
    
    def get_logs(self, filters: Dict = None, page: int = 1, per_page: int = 50) -> Dict:
        """Get logs with filtering and pagination"""
        try:
            # ✅ FIX: Process date filters for Vietnam timezone
            if filters:
                if filters.get('start_date'):
                    filters['start_date'] = self._parse_date_filter(filters['start_date'])
                if filters.get('end_date'):
                    filters['end_date'] = self._parse_date_filter(filters['end_date'])
                if filters.get('since'):
                    filters['since'] = self._parse_date_filter(filters['since'])
                if filters.get('until'):
                    filters['until'] = self._parse_date_filter(filters['until'])
            
            result = self.model.get_logs(filters, page, per_page)
            
            # ✅ ADD: Current time info
            result['current_time'] = self._now_local().isoformat()
            result['timezone'] = 'UTC+7'
            
            return result
            
        except Exception as e:
            logger.error(f"Error getting logs: {e}")
            return {
                "logs": [],
                "total": 0,
                "page": page,
                "per_page": per_page,
                "pages": 0,
                "error": str(e),
                "timezone": "UTC+7"
            }
    
    # ✅ ADD: Alternative method with limit parameter for backward compatibility
    def find_logs(self, filters: Dict = None, limit: int = 50, offset: int = 0) -> List[Dict]:
        """Find logs with simple limit/offset - for backward compatibility"""
        try:
            page = (offset // limit) + 1
            result = self.get_logs(filters, page, limit)
            return result.get('logs', [])
        except Exception as e:
            logger.error(f"Error finding logs: {e}")
            return []
    
    def _parse_date_filter(self, date_str: str) -> datetime:
        """Parse date filter string to Vietnam timezone"""
        try:
            if isinstance(date_str, datetime):
                return self._ensure_vietnam_timezone(date_str)
            
            # Parse various date formats
            if 'T' in date_str:
                # ISO format
                dt = datetime.fromisoformat(date_str.replace('Z', '+00:00'))
            else:
                # Date only - assume start of day in Vietnam
                dt = datetime.strptime(date_str, '%Y-%m-%d')
                dt = dt.replace(tzinfo=self.vietnam_timezone)
            
            return self._ensure_vietnam_timezone(dt)
            
        except (ValueError, TypeError) as e:
            logger.warning(f"Failed to parse date filter '{date_str}': {e}")
            return None
    
    def get_log_by_id(self, log_id: str) -> Dict:
        """Get single log by ID"""
        return self.model.get_log_by_id(log_id)
    
    def delete_log(self, log_id: str) -> bool:
        """Delete log by ID"""
        return self.model.delete_log(log_id)
    
    def clear_logs(self, filters: Dict = None) -> int:
        """Clear logs with optional filters"""
        return self.model.clear_logs(filters)
    
    # ✅ ADD: Missing get_logs_summary method
    def get_logs_summary(self, period: str = "day") -> Dict:
        """Get logs summary for different time periods"""
        current_time = self._now_local()
        
        if period == "hour":
            since = current_time - timedelta(hours=1)
        elif period == "day":
            since = current_time - timedelta(days=1)
        elif period == "week":
            since = current_time - timedelta(weeks=1)
        elif period == "month":
            since = current_time - timedelta(days=30)
        else:
            since = current_time - timedelta(days=1)
        
        summary = self.model.get_logs_summary(since)
        
        # ✅ ADD: Time period info
        summary['period'] = period
        summary['period_start'] = since.isoformat()
        summary['period_end'] = current_time.isoformat()
        summary['timezone'] = 'UTC+7'
        
        return summary
    
    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent logs"""
        return self.model.get_recent_logs(limit)
    
    def get_hourly_stats(self, hours: int = 24) -> List[Dict]:
        """Get hourly statistics"""
        return self.model.get_hourly_stats(hours)
    
    def search_logs(self, search_term: str, limit: int = 100) -> List[Dict]:
        """Search logs by domain or other criteria"""
        filters = {}
        
        # Search in domain field
        if search_term:
            filters['domain'] = search_term
        
        return self.model.find_logs(
            query=self.model.build_query_from_filters(filters),
            limit=limit
        )
    
    # ✅ REMOVE DUPLICATE get_recent_logs method - only keep one version
    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent logs with Vietnam timezone"""
        try:
            logs = self.model.get_recent_logs(limit)
            
            # ✅ ADD: Additional Vietnam timezone formatting
            for log in logs:
                if 'timestamp' in log:
                    # Parse timestamp if it's a string
                    if isinstance(log['timestamp'], str):
                        try:
                            timestamp = datetime.fromisoformat(log['timestamp'].replace('Z', '+00:00'))
                            vn_time = self._ensure_vietnam_timezone(timestamp)
                        except:
                            vn_time = self._now_local()
                    else:
                        vn_time = self._ensure_vietnam_timezone(log['timestamp'])
                    
                    # Add formatted times
                    log['vn_timestamp'] = vn_time.isoformat()
                    log['vn_display_time'] = vn_time.strftime('%Y-%m-%d %H:%M:%S')
                    log['vn_time_short'] = vn_time.strftime('%H:%M:%S')
                    log['vn_date'] = vn_time.strftime('%Y-%m-%d')
            
            return logs
            
        except Exception as e:
            logger.error(f"Error getting recent logs: {e}")
            return []
    
    # ✅ ADD: Comprehensive timezone info method
    def get_timezone_info(self) -> Dict:
        """Get comprehensive timezone information"""
        current_time = self._now_local()
        utc_time = datetime.now(timezone.utc)
        
        return {
            "timezone": "UTC+7",
            "timezone_name": "Asia/Ho_Chi_Minh",
            "timezone_offset": "+07:00",
            "current_vn_time": current_time.isoformat(),
            "current_utc_time": utc_time.isoformat(),
            "display_time": current_time.strftime('%Y-%m-%d %H:%M:%S'),
            "time_format": "24-hour",
            "date_format": "YYYY-MM-DD",
            "offset_hours": 7,
            "dst_active": False,  # Vietnam doesn't use DST
            "country": "Vietnam"
        }
    
    # ✅ ADD: Batch operations with timezone
    def insert_multiple_logs(self, logs_list: List[Dict], agent_id: str = None) -> Dict:
        """Insert multiple logs with Vietnam timezone processing"""
        try:
            current_time = self._now_local()
            processed_logs = []
            
            for log_data in logs_list:
                # Process timestamp
                if 'timestamp' not in log_data:
                    log_data['timestamp'] = current_time
                else:
                    log_data['timestamp'] = self._parse_date_filter(log_data['timestamp'])
                
                # Add metadata
                log_data['server_received_at'] = current_time
                if agent_id:
                    log_data['agent_id'] = agent_id
                
                processed_logs.append(log_data)
            
            # Insert to database
            inserted_ids = self.model.insert_logs(processed_logs)
            
            return {
                "success": True,
                "inserted_count": len(inserted_ids),
                "inserted_ids": inserted_ids,
                "timezone": "UTC+7",
                "timestamp": current_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error inserting multiple logs: {e}")
            return {
                "success": False,
                "error": str(e),
                "timezone": "UTC+7"
            }
    
    # ✅ ADD: Statistics with time periods
    def get_detailed_stats(self, hours: int = 24) -> Dict:
        """Get detailed statistics for specified hours"""
        try:
            current_time = self._now_local()
            start_time = current_time - timedelta(hours=hours)
            
            # Basic stats
            summary = self.model.get_logs_summary(start_time)
            
            # Hourly breakdown
            hourly_stats = self.model.get_hourly_stats(hours)
            
            # Top domains/agents
            filters = {
                'since': start_time.isoformat(),
                'until': current_time.isoformat()
            }
            
            return {
                **summary,
                "hourly_breakdown": hourly_stats,
                "period_hours": hours,
                "period_start": start_time.isoformat(),
                "period_end": current_time.isoformat(),
                "timezone": "UTC+7",
                "last_updated": current_time.isoformat()
            }
            
        except Exception as e:
            logger.error(f"Error getting detailed stats: {e}")
            return {
                "error": str(e),
                "timezone": "UTC+7"
            }
    
    # ✅ ADD: Export logs with timezone
    def export_logs(self, filters: Dict = None, format: str = "json") -> Dict:
        """Export logs with Vietnam timezone formatting"""
        try:
            # Get all matching logs (no pagination)
            all_logs = []
            page = 1
            per_page = 1000
            
            while True:
                result = self.get_logs(filters, page, per_page)
                logs = result.get('logs', [])
                
                if not logs:
                    break
                
                all_logs.extend(logs)
                
                if len(logs) < per_page:
                    break
                
                page += 1
            
            # Format for export
            export_data = {
                "export_info": {
                    "total_logs": len(all_logs),
                    "exported_at": self._now_local().isoformat(),
                    "timezone": "UTC+7",
                    "format": format,
                    "filters": filters or {}
                },
                "logs": all_logs
            }
            
            return {
                "success": True,
                "data": export_data,
                "count": len(all_logs),
                "timezone": "UTC+7"
            }
            
        except Exception as e:
            logger.error(f"Error exporting logs: {e}")
            return {
                "success": False,
                "error": str(e),
                "timezone": "UTC+7"
            }