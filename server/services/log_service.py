"""
Log Service - Business logic for log operations
UTC ONLY - Clean and simple
"""

import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta, timezone
from models.log_model import LogModel

# Import time utilities - UTC ONLY
from time_utils import now_utc, to_utc_naive, parse_agent_timestamp, now_iso

class LogService:
    """Service class for log business logic - UTC ONLY"""
    
    def __init__(self, log_model: LogModel, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = log_model
        self.socketio = socketio
    
    def receive_logs(self, logs_data: Dict, agent_id: str = None) -> Dict:
        """Receive and process logs from agents - UTC ONLY"""
        try:
            # Extract logs from data
            logs = logs_data.get('logs', [])
            if not logs:
                return {"success": False, "error": "No logs provided"}
            
            # Use UTC time for server processing
            current_time = to_utc_naive(now_utc())  # UTC naive for MongoDB
            
            # Process each log entry
            valid_logs = []
            for log in logs:
                try:
                    # Enhanced protocol processing
                    protocol = log.get("protocol", "unknown")
                    port = log.get("port", "unknown")
                    
                    # Smart protocol detection
                    if protocol == "unknown" and port != "unknown":
                        if str(port) == "443":
                            protocol = "HTTPS"
                        elif str(port) == "80":
                            protocol = "HTTP"
                        elif str(port) == "53":
                            protocol = "DNS"
                        else:
                            protocol = f"TCP/{port}"
                    
                    # Enhanced source IP processing
                    source_ip = log.get("source_ip") or log.get("src_ip") or log.get("local_ip") or "unknown"
                    
                    # Enhanced destination processing
                    destination = (
                        log.get("destination") or 
                        log.get("domain") or 
                        log.get("url") or 
                        log.get("dest_ip") or 
                        log.get("ip") or 
                        "unknown"
                    )
                    
                    # Create processed log entry
                    processed_log = {
                        "agent_id": agent_id or log.get("agent_id", "unknown"),
                        "level": log.get("level", "INFO"),
                        "action": log.get("action", "UNKNOWN"),
                        "domain": log.get("domain", "unknown"),
                        "destination": destination,
                        "source_ip": source_ip,
                        "dest_ip": log.get("dest_ip") or log.get("ip") or "unknown",
                        "protocol": protocol,
                        "port": str(port) if port != "unknown" else "unknown",
                        "message": log.get("message", "Log entry"),
                        "source": log.get("source", "agent"),
                        "connection_type": log.get("connection_type", "outbound"),
                        "service_type": log.get("service_type", "unknown"),
                        "process_name": log.get("process_name"),
                        "process_pid": log.get("process_pid")
                    }
                    
                    # Format display fields
                    if protocol != "unknown" and port != "unknown":
                        processed_log["protocol_display"] = f"{protocol}:{port}"
                    else:
                        processed_log["protocol_display"] = protocol
                    
                    processed_log["source_display"] = source_ip if source_ip != "unknown" else "Local"
                    
                    # Timestamp processing - UTC ONLY
                    if 'timestamp' in log and log['timestamp']:
                        try:
                            # Parse agent timestamp using UTC parsing
                            if isinstance(log['timestamp'], str):
                                agent_time = parse_agent_timestamp(log['timestamp'])  # UTC parsing
                            else:
                                # Convert to UTC
                                from datetime import datetime, timezone
                                if isinstance(log['timestamp'], datetime):
                                    if log['timestamp'].tzinfo is None:
                                        agent_time = log['timestamp'].replace(tzinfo=timezone.utc)
                                    else:
                                        agent_time = log['timestamp'].astimezone(timezone.utc)
                                else:
                                    agent_time = now_utc()
                            
                            # Convert to naive for MongoDB storage
                            processed_log['timestamp'] = agent_time.replace(tzinfo=None)
                            processed_log['timestamp_source'] = 'agent'
                            
                        except Exception as e:
                            self.logger.warning(f"Invalid timestamp format '{log.get('timestamp')}': {e}")
                            processed_log['timestamp'] = current_time
                            processed_log['timestamp_source'] = 'server_fallback'
                    else:
                        processed_log['timestamp'] = current_time
                        processed_log['timestamp_source'] = 'server'
                    
                    # Add server received timestamp
                    processed_log['server_received_at'] = current_time
                    
                    # Copy additional fields if they exist
                    optional_fields = ['reason', 'firewall_mode', 'handled_by_firewall', 
                                     'domain_check', 'ip_check', 'url', 'ip']
                    for field in optional_fields:
                        if field in log and log[field] is not None:
                            processed_log[field] = log[field]
                    
                    # Normalize action values
                    action = processed_log['action'].upper()
                    if action in ['ALLOW', 'ALLOWED']:
                        processed_log['action'] = 'ALLOWED'
                        if processed_log['level'] == 'INFO':
                            processed_log['level'] = 'ALLOWED'
                    elif action in ['BLOCK', 'BLOCKED', 'DENY', 'DENIED']:
                        processed_log['action'] = 'BLOCKED'
                        if processed_log['level'] in ['INFO', 'WARNING']:
                            processed_log['level'] = 'BLOCKED'
                    
                    valid_logs.append(processed_log)
                    
                except Exception as e:
                    self.logger.warning(f"Error processing log entry: {e}")
                    # Create fallback log
                    fallback_log = {
                        "timestamp": current_time,
                        "server_received_at": current_time,
                        "agent_id": agent_id or "unknown",
                        "level": "ERROR",
                        "action": "ERROR",
                        "domain": "processing_error",
                        "destination": "processing_error",
                        "source_ip": "unknown",
                        "dest_ip": "unknown",
                        "protocol": "unknown",
                        "port": "unknown",
                        "message": f"Failed to process log: {str(e)}",
                        "source": "log_processing_error",
                        "original_data": str(log)[:200] + "..." if len(str(log)) > 200 else str(log),
                        "processing_error": str(e),
                        "timestamp_source": "server"
                    }
                    valid_logs.append(fallback_log)
                    continue
            
            # Check if we have valid logs
            if not valid_logs:
                return {"success": False, "error": "No valid logs to process"}
            
            # Store in database
            inserted_ids = self.model.insert_logs(valid_logs)
            
            # Real-time broadcast via Socket.IO - UTC only
            if self.socketio:
                for log in valid_logs[-5:]:  # Broadcast last 5 logs
                    # Format for frontend
                    broadcast_log = {
                        'timestamp': log['timestamp'].isoformat() if hasattr(log['timestamp'], 'isoformat') else str(log['timestamp']),
                        'display_time': log['timestamp'].strftime('%H:%M:%S') if hasattr(log['timestamp'], 'strftime') else str(log['timestamp'])[:8],
                        'domain': log.get('domain', 'unknown'),
                        'destination': log.get('destination', 'unknown'),
                        'action': log.get('action', 'UNKNOWN'),
                        'level': log.get('level', 'INFO'),
                        'agent_id': log.get('agent_id', 'unknown'),
                        'source_ip': log.get('source_ip', 'unknown'),
                        'dest_ip': log.get('dest_ip', 'unknown'),
                        'protocol': log.get('protocol', 'unknown'),
                        'port': str(log.get('port', 'unknown')),
                        'message': log.get('message', 'Log entry')
                    }
                    self.socketio.emit('new_log', broadcast_log)
            
            self.logger.info(f"Successfully processed {len(valid_logs)} logs from agent {agent_id}")
            
            return {
                "success": True,
                "message": f"Successfully processed {len(valid_logs)} logs",
                "inserted_ids": inserted_ids,
                "processed_count": len(valid_logs),
                "server_time": now_iso()  # UTC ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error receiving logs: {e}")
            return {
                "success": False, 
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def get_all_logs(self, filters: Dict = None, limit: int = 100, offset: int = 0) -> Dict:
        """Get all logs with filtering - UTC ONLY"""
        try:
            # Build query from filters
            query = {}
            
            if filters:
                if filters.get('level'):
                    query['level'] = filters['level']
                
                if filters.get('action'):
                    query['action'] = filters['action']
                
                if filters.get('agent_id'):
                    query['agent_id'] = filters['agent_id']
                
                if filters.get('search'):
                    search_term = filters['search']
                    query['$or'] = [
                        {'domain': {'$regex': search_term, '$options': 'i'}},
                        {'destination': {'$regex': search_term, '$options': 'i'}},
                        {'source_ip': {'$regex': search_term, '$options': 'i'}},
                        {'dest_ip': {'$regex': search_term, '$options': 'i'}},
                        {'message': {'$regex': search_term, '$options': 'i'}}
                    ]
                
                # Time range filter - UTC
                if filters.get('time_range'):
                    time_range = filters['time_range']
                    current_time = to_utc_naive(now_utc())  # UTC naive for MongoDB
                    
                    if time_range == "1h":
                        since_time = current_time - timedelta(hours=1)
                    elif time_range == "24h":
                        since_time = current_time - timedelta(hours=24)
                    elif time_range == "7d":
                        since_time = current_time - timedelta(days=7)
                    elif time_range == "30d":
                        since_time = current_time - timedelta(days=30)
                    else:
                        since_time = None
                    
                    if since_time:
                        query["timestamp"] = {"$gte": since_time}
                
                # Date range filters - UTC
                if filters.get('start_date'):
                    try:
                        start_date = parse_agent_timestamp(filters['start_date'])
                        query['timestamp'] = query.get('timestamp', {})
                        query['timestamp']['$gte'] = to_utc_naive(start_date)
                    except Exception as e:
                        self.logger.warning(f"Invalid start_date filter: {e}")
                
                if filters.get('end_date'):
                    try:
                        end_date = parse_agent_timestamp(filters['end_date'])
                        query['timestamp'] = query.get('timestamp', {})
                        query['timestamp']['$lte'] = to_utc_naive(end_date)
                    except Exception as e:
                        self.logger.warning(f"Invalid end_date filter: {e}")
            
            self.logger.info(f"Getting logs with query: {query}, limit: {limit}, offset: {offset}")
            
            # Get logs and total count
            logs = self.model.find_all_logs(query, limit=limit, offset=offset)
            total_count = self.model.count_logs(query)
            
            self.logger.info(f"Found {len(logs)} logs, total count: {total_count}")
            
            # Format for response
            formatted_logs = []
            for log in logs:
                try:
                    formatted_log = {
                        "id": str(log.get("_id", "")),
                        "timestamp": log.get("timestamp"),
                        "agent_id": log.get("agent_id", "unknown"),
                        "level": log.get("level", "INFO"),
                        "action": log.get("action", "UNKNOWN"),
                        "domain": log.get("domain", "unknown"),
                        "destination": log.get("destination", "unknown"),
                        "source_ip": log.get("source_ip", "unknown"),
                        "dest_ip": log.get("dest_ip", "unknown"),
                        "protocol": log.get("protocol", "unknown"),
                        "port": str(log.get("port", "unknown")),
                        "message": log.get("message", "Log entry"),
                        "source": log.get("source", "agent")
                    }
                    
                    # Handle timestamps - UTC only
                    if log.get("timestamp"):
                        try:
                            timestamp = log["timestamp"]
                            if hasattr(timestamp, 'isoformat'):
                                # Convert to UTC if needed
                                if timestamp.tzinfo is None:
                                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                                else:
                                    timestamp = timestamp.astimezone(timezone.utc)
                                formatted_log["timestamp"] = timestamp.isoformat()
                            elif isinstance(timestamp, str):
                                formatted_log["timestamp"] = timestamp
                            else:
                                formatted_log["timestamp"] = str(timestamp)
                        except Exception as e:
                            self.logger.warning(f"Error formatting timestamp: {e}")
                            formatted_log["timestamp"] = now_iso()
                    
                    # Add optional fields
                    for field in ["reason", "firewall_mode", "handled_by_firewall", "display_time"]:
                        if log.get(field):
                            formatted_log[field] = log[field]
                    
                    formatted_logs.append(formatted_log)
                    
                except Exception as e:
                    self.logger.error(f"Error formatting log entry: {e}")
                    continue
            
            result = {
                "logs": formatted_logs,
                "total": total_count,
                "limit": limit,
                "offset": offset,
                "has_more": offset + limit < total_count,
                "success": True,
                "server_time": now_iso()  # UTC ISO
            }
            
            self.logger.info(f"Returning {len(formatted_logs)} formatted logs")
            return result
            
        except Exception as e:
            self.logger.error(f"Error getting logs: {e}")
            import traceback
            traceback.print_exc()
            return {
                "success": False, 
                "error": str(e), 
                "logs": [], 
                "total": 0,
                "server_time": now_iso()  # UTC ISO
            }
    
    def clear_logs(self, filters: Dict = None) -> Dict:
        """Clear logs with optional filters - UTC ONLY"""
        try:
            query = {}
            
            if filters:
                if filters.get('level'):
                    query['level'] = filters['level']
                
                if filters.get('action'):
                    query['action'] = filters['action']
                
                if filters.get('agent_id'):
                    query['agent_id'] = filters['agent_id']
                
                # Handle ObjectId filters for specific log deletion
                if filters.get('_id'):
                    query['_id'] = filters['_id']
            
            deleted_count = self.model.delete_logs(query)
            
            self.logger.info(f"Cleared {deleted_count} logs with filters: {filters}")
            
            return {
                "success": True,
                "message": f"Deleted {deleted_count} logs",
                "deleted_count": deleted_count,
                "server_time": now_iso()  # UTC ISO
            }
            
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            return {
                "success": False,
                "error": str(e),
                "deleted_count": 0,
                "server_time": now_iso()  # UTC ISO
            }
    
    def export_logs(self, filters: Dict = None, format: str = 'json') -> Dict:
        """Export logs in specified format - UTC ONLY"""
        try:
            # Get all logs matching filters (no pagination for export)
            result = self.get_all_logs(filters, limit=10000, offset=0)
            
            if not result.get('success'):
                return result
            
            logs = result['logs']
            
            if format == 'csv':
                import csv
                import io
                
                output = io.StringIO()
                if logs:
                    fieldnames = logs[0].keys()
                    writer = csv.DictWriter(output, fieldnames=fieldnames)
                    writer.writeheader()
                    
                    for log in logs:
                        # Convert datetime objects to strings for CSV
                        csv_log = {}
                        for key, value in log.items():
                            if isinstance(value, datetime):
                                csv_log[key] = value.isoformat()
                            else:
                                csv_log[key] = str(value) if value is not None else ''
                        writer.writerow(csv_log)
                
                return {
                    "success": True,
                    "data": output.getvalue(),
                    "count": len(logs),
                    "format": format,
                    "server_time": now_iso()  # UTC ISO
                }
            else:
                # JSON format
                return {
                    "success": True,
                    "data": logs,
                    "count": len(logs),
                    "format": format,
                    "server_time": now_iso()  # UTC ISO
                }
                
        except Exception as e:
            self.logger.error(f"Error exporting logs: {e}")
            return {
                "success": False,
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def get_comprehensive_statistics(self, filters: Dict = None) -> Dict:
        """Get comprehensive log statistics - UTC ONLY"""
        try:
            self.logger.info(f"Calculating comprehensive statistics with filters: {filters}")
            
            # Check if we have any filters
            has_filters = bool(filters and any(filters.values()))
            
            # Get total counts (no filters)
            total_stats = {
                "total": self.model.count_logs({}),
                "allowed": self.model.count_logs({"action": "ALLOWED"}),
                "blocked": self.model.count_logs({"action": "BLOCKED"}),
                "warnings": self.model.count_logs({"level": "WARNING"})
            }
            
            # Get filtered counts if filters exist
            filtered_stats = {}
            if has_filters:
                query = self._build_query_from_filters(filters)
                self.logger.info(f"Filter query: {query}")
                
                filtered_stats = {
                    "filtered_total": self.model.count_logs(query),
                    "filtered_allowed": self.model.count_logs({**query, "action": "ALLOWED"}),
                    "filtered_blocked": self.model.count_logs({**query, "action": "BLOCKED"}),
                    "filtered_warnings": self.model.count_logs({**query, "level": "WARNING"})
                }
            
            # Combine results
            result = {
                **total_stats,
                **filtered_stats,
                "has_filters": has_filters,
                "server_time": now_iso()  # UTC ISO
            }
            
            self.logger.info(f"Statistics result: {result}")
            return result
            
        except Exception as e:
            self.logger.error(f"Error getting comprehensive statistics: {e}")
            return {
                "total": 0,
                "allowed": 0,
                "blocked": 0,
                "warnings": 0,
                "has_filters": False,
                "error": str(e),
                "server_time": now_iso()  # UTC ISO
            }
    
    def _build_query_from_filters(self, filters: Dict) -> Dict:
        """Build MongoDB query from filters - UTC ONLY"""
        query = {}
        
        if filters.get("level"):
            query["level"] = filters["level"]
        
        if filters.get("action"):
            query["action"] = filters["action"]
        
        if filters.get("agent_id"):
            query["agent_id"] = filters["agent_id"]
        
        if filters.get("search"):
            search_term = filters["search"]
            query["$or"] = [
                {"domain": {"$regex": search_term, "$options": "i"}},
                {"destination": {"$regex": search_term, "$options": "i"}},
                {"source_ip": {"$regex": search_term, "$options": "i"}},
                {"dest_ip": {"$regex": search_term, "$options": "i"}},
                {"message": {"$regex": search_term, "$options": "i"}}
            ]
        
        # Time range filter - UTC
        if filters.get("time_range"):
            time_range = filters["time_range"]
            current_time = to_utc_naive(now_utc())  # UTC naive for MongoDB
            
            if time_range == "1h":
                since_time = current_time - timedelta(hours=1)
            elif time_range == "24h":
                since_time = current_time - timedelta(hours=24)
            elif time_range == "7d":
                since_time = current_time - timedelta(days=7)
            elif time_range == "30d":
                since_time = current_time - timedelta(days=30)
            else:
                since_time = None
            
            if since_time:
                query["timestamp"] = {"$gte": since_time}
        
        # Date range filter - UTC
        if filters.get("start_date") or filters.get("end_date"):
            date_query = {}
            if filters.get("start_date"):
                try:
                    start_dt = parse_agent_timestamp(filters["start_date"])
                    # Convert to naive for MongoDB query
                    date_query["$gte"] = start_dt.replace(tzinfo=None)
                except Exception:
                    pass
            
            if filters.get("end_date"):
                try:
                    end_dt = parse_agent_timestamp(filters["end_date"])
                    # Convert to naive for MongoDB query
                    date_query["$lte"] = end_dt.replace(tzinfo=None)
                except Exception:
                    pass
            
            if date_query:
                query["timestamp"] = date_query
        
        self.logger.debug(f"Built query from filters {filters}: {query}")
        return query
    
    def get_total_count(self) -> int:
        """Get total log count"""
        try:
            return self.model.count_logs({})
        except Exception as e:
            self.logger.error(f"Error getting total count: {e}")
            return 0
    
    def get_count_by_action(self, action: str) -> int:
        """Get count by action type"""
        try:
            query = {"action": action.upper()}
            return self.model.count_logs(query)
        except Exception as e:
            self.logger.error(f"Error getting count by action: {e}")
            return 0
    
    def get_recent_logs(self, limit: int = 10) -> List[Dict]:
        """Get recent logs - UTC ONLY"""
        try:
            logs = self.model.find_all_logs({}, limit=limit, offset=0)
            
            # Format for display
            formatted_logs = []
            for log in logs:
                formatted_log = {
                    "timestamp": log.get("timestamp"),
                    "domain": log.get("domain", "unknown"),
                    "action": log.get("action", "UNKNOWN"),
                    "agent_id": log.get("agent_id", "unknown"),
                    "level": log.get("level", "INFO")
                }
                
                # Format timestamp for display - UTC
                if log.get("timestamp"):
                    try:
                        if hasattr(log["timestamp"], 'strftime'):
                            formatted_log["display_time"] = log["timestamp"].strftime("%H:%M:%S")
                        else:
                            formatted_log["display_time"] = str(log["timestamp"])[:8]
                    except:
                        formatted_log["display_time"] = "00:00:00"
                
                formatted_logs.append(formatted_log)
            
            return formatted_logs
            
        except Exception as e:
            self.logger.error(f"Error getting recent logs: {e}")
            return []