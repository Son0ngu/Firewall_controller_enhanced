"""
Log Controller - handles log HTTP requests
vietnam ONLY - Clean and simple
"""

from flask import Blueprint, request, jsonify, Response
from typing import Dict, Tuple
from models.log_model import LogModel
from services.log_service import LogService
import logging

# Import time utilities - vietnam ONLY
from time_utils import now_iso

class LogController:
    """Controller for log operations"""
    
    def __init__(self, log_model: LogModel, log_service: LogService, socketio=None):
        self.model = log_model
        self.service = log_service
        self.socketio = socketio
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Create Blueprint
        self.blueprint = Blueprint('logs', __name__)
        self._register_routes()
    
    def _register_routes(self):
        """Register all log routes"""
        
        #  IMPORTANT: Stats route MUST be before generic /logs route
        self.blueprint.add_url_rule('/logs/stats', 
                                   methods=['GET'], 
                                   view_func=self.get_statistics)
        
        # POST /api/logs - Receive logs from agents
        self.blueprint.add_url_rule('/logs', 
                                   methods=['POST'], 
                                   view_func=self.receive_logs)
        
        # GET /api/logs - Get all logs
        self.blueprint.add_url_rule('/logs', 
                                   methods=['GET'], 
                                   view_func=self.list_logs)
        
        #  ADD: DELETE /api/logs/clear - Clear logs
        self.blueprint.add_url_rule('/logs/clear', 
                                   methods=['DELETE'], 
                                   view_func=self.clear_logs)
        
        # DELETE /api/logs - Clear all logs (legacy)
        self.blueprint.add_url_rule('/logs', 
                                   methods=['DELETE'], 
                                   view_func=self.clear_logs)
        
        # GET /api/logs/export - Export logs
        self.blueprint.add_url_rule('/logs/export', 
                                   methods=['GET'], 
                                   view_func=self.export_logs)
    
    def receive_logs(self):
        """Receive logs from agent"""
        try:
            if not request.is_json:
                return self._error_response("Request must be JSON", 400)
            
            data = request.get_json()
            if not data:
                return self._error_response("Invalid JSON data", 400)
            
            # Get agent info from request
            agent_id = request.headers.get('X-Agent-ID') or data.get('agent_id')
            client_ip = request.remote_addr
            
            self.logger.info(f"Receiving logs from agent {agent_id} at {client_ip}")
            
            # Process logs using service
            result = self.service.receive_logs(data, agent_id)
            
            if result.get("success"):
                return jsonify(result), 201
            else:
                return self._error_response(result.get("error", "Failed to process logs"), 400)
                
        except Exception as e:
            self.logger.error(f"Error receiving logs: {e}")
            return self._error_response("Failed to receive logs", 500)
    
    def list_logs(self):
        """Get all logs with filtering and pagination"""
        try:
            # Get query parameters
            filters = self._get_filter_params()
            limit = int(request.args.get('limit', 100))
            offset = int(request.args.get('offset', 0))
            
            # Call service method
            result = self.service.get_all_logs(filters, limit, offset)
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error listing logs: {e}")
            return self._error_response("Failed to list logs", 500)
    
    def clear_logs(self):
        """Clear logs with optional filters - Enhanced version"""
        try:
            # Get request data
            if request.is_json:
                data = request.get_json() or {}
            else:
                data = {}
            
            # Get filters from query parameters OR request body
            filters = {}
            
            # Check query parameters first
            query_filters = self._get_filter_params()
            if query_filters:
                filters.update(query_filters)
            
            # Check request body for additional filters
            if data.get('filters'):
                filters.update(data['filters'])
            
            # Handle specific clear actions
            clear_action = data.get('action', 'all')
            
            if clear_action == 'selected' and data.get('log_ids'):
                # Clear specific logs by IDs
                from bson import ObjectId
                log_ids = data['log_ids']
                object_ids = []
                
                for log_id in log_ids:
                    try:
                        object_ids.append(ObjectId(log_id))
                    except Exception:
                        # If not ObjectId, treat as string ID
                        pass
                
                if object_ids:
                    filters['_id'] = {'$in': object_ids}
            
            elif clear_action == 'old':
                # Clear logs older than 30 days
                from datetime import datetime, timedelta, timezone
                thirty_days_ago = datetime.now(timezone.vietnam) - timedelta(days=30)
                filters['timestamp'] = {'$lt': thirty_days_ago}
            
            elif clear_action == 'filtered':
                # Use provided filters (already set above)
                pass
            
            # Default: clear all (no additional filters)
            
            self.logger.info(f"Clearing logs with action: {clear_action}, filters: {filters}")
            
            # Call service method
            result = self.service.clear_logs(filters)
            
            if result.get("success"):
                # Emit real-time update - vietnam only
                if self.socketio:
                    self.socketio.emit('logs_cleared', {
                        'action': clear_action,
                        'deleted_count': result.get('deleted_count', 0),
                        'timestamp': now_iso()  # vietnam ISO
                    })
                
                return jsonify(result), 200
            else:
                return self._error_response(result.get("error", "Failed to clear logs"), 500)
                
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            import traceback
            traceback.print_exc()
            return self._error_response("Failed to clear logs", 500)
    
    def export_logs(self):
        """Export logs"""
        try:
            filters = self._get_filter_params()
            format = request.args.get('format', 'json')
            
            # Call service method
            result = self.service.export_logs(filters, format)
            
            if result.get("success"):
                if format == 'csv':
                    return Response(
                        result["data"],
                        mimetype="text/csv",
                        headers={"Content-disposition": "attachment; filename=logs.csv"}
                    )
                else:
                    return jsonify(result), 200
            else:
                return self._error_response(result.get("error", "Failed to export logs"), 500)
                
        except Exception as e:
            self.logger.error(f"Error exporting logs: {e}")
            return self._error_response("Failed to export logs", 500)
    
    def get_log_statistics(self):
        """Get comprehensive log statistics for frontend"""
        try:
            filters = self._get_filter_params()
            
            self.logger.info(f"Getting log statistics with filters: {filters}")
            
            # Get statistics from service
            stats = self.service.get_comprehensive_statistics(filters)
            
            self.logger.info(f"Statistics calculated: {stats}")
            
            return jsonify({
                "success": True,
                "total": stats.get("total", 0),
                "allowed": stats.get("allowed", 0),
                "blocked": stats.get("blocked", 0),
                "warnings": stats.get("warnings", 0),
                "filtered_total": stats.get("filtered_total", 0),
                "filtered_allowed": stats.get("filtered_allowed", 0),
                "filtered_blocked": stats.get("filtered_blocked", 0),
                "filtered_warnings": stats.get("filtered_warnings", 0),
                "has_filters": stats.get("has_filters", False),
                "timestamp": now_iso()  # vietnam ISO
            }), 200
            
        except Exception as e:
            self.logger.error(f"Error getting log statistics: {e}")
            return jsonify({
                "success": False,
                "error": str(e),
                "total": 0,
                "allowed": 0,
                "blocked": 0,
                "warnings": 0,
                "timestamp": now_iso()  # vietnam ISO
            }), 500
    
    def get_statistics(self):
        """Get basic log statistics (legacy endpoint)"""
        try:
            # Call the comprehensive method
            return self.get_log_statistics()
            
        except Exception as e:
            self.logger.error(f"Error getting basic statistics: {e}")
            return self._error_response("Failed to get statistics", 500)
    
    def _get_filter_params(self) -> Dict:
        """Extract filter parameters from request"""
        filters = {}
        
        # Basic filters
        if request.args.get('level'):
            filters['level'] = request.args.get('level')
        
        if request.args.get('action'):
            filters['action'] = request.args.get('action')
        
        if request.args.get('agent_id'):
            filters['agent_id'] = request.args.get('agent_id')
        
        if request.args.get('search'):
            filters['search'] = request.args.get('search')
        
        # Date filters
        if request.args.get('start_date'):
            filters['start_date'] = request.args.get('start_date')
        
        if request.args.get('end_date'):
            filters['end_date'] = request.args.get('end_date')
        
        return filters
    
    def _error_response(self, message: str, status_code: int) -> Tuple:
        """Create error response - vietnam only"""
        return jsonify({
            "success": False,
            "error": message,
            "timestamp": now_iso()  # vietnam ISO
        }), status_code