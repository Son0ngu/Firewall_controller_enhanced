"""
Log Controller - handles log HTTP requests
"""

import logging
from flask import Blueprint, request, jsonify
from typing import Dict, Tuple
from models.log_model import LogModel
from services.log_service import LogService

class LogController:
    """Controller for log operations"""
    
    def __init__(self, log_model: LogModel, log_service: LogService, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = log_model
        self.service = log_service
        self.socketio = socketio
        self.blueprint = Blueprint('logs', __name__)
        self._register_routes()
    
    def _register_routes(self):
        """Register routes for this controller"""
        self.blueprint.add_url_rule('/logs', 'receive_logs', self.receive_logs, methods=['POST'])
        self.blueprint.add_url_rule('/logs', 'get_logs', self.get_logs, methods=['GET'])
        self.blueprint.add_url_rule('/logs', 'clear_all_logs', self.clear_all_logs, methods=['DELETE'])
        self.blueprint.add_url_rule('/logs/summary', 'get_logs_summary', self.get_logs_summary, methods=['GET'])
        self.blueprint.add_url_rule('/logs/<log_id>', 'delete_log', self.delete_log, methods=['DELETE'])
        self.blueprint.add_url_rule('/logs/clear', 'clear_logs', self.clear_logs, methods=['POST'])
        self.blueprint.add_url_rule('/logs/receive', 'receive_logs_agent', self.receive_logs_agent, methods=['POST'])
        self.blueprint.add_url_rule('/logs/timezone-info', 'get_timezone_info', self.get_timezone_info, methods=['GET'])
    
    def _success_response(self, data=None, message="Success", status_code=200) -> Tuple:
        """Helper method for success responses"""
        response = {"success": True, "message": message}
        if data is not None:
            response.update(data)
        return jsonify(response), status_code
    
    def _error_response(self, message: str, status_code=400) -> Tuple:
        """Helper method for error responses"""
        return jsonify({"success": False, "error": message}), status_code
    
    def _validate_json_request(self, required_fields=None) -> Dict:
        """Validate JSON request"""
        if not request.is_json:
            raise ValueError("Request must be JSON")
        
        data = request.get_json()
        if not data:
            raise ValueError("Invalid JSON data")
        
        if required_fields:
            missing_fields = [field for field in required_fields if field not in data]
            if missing_fields:
                raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")
        
        return data
    
    def _get_pagination_params(self) -> Dict:
        """Get pagination parameters - Convert to page/per_page format"""
        try:
            # ✅ FIX: Convert limit/skip to page/per_page
            limit = min(int(request.args.get('limit', 50)), 1000)
            skip = int(request.args.get('skip', 0))
            
            # Calculate page from skip and limit
            page = (skip // limit) + 1 if limit > 0 else 1
            per_page = limit
            
            # Also support direct page/per_page parameters
            if request.args.get('page'):
                page = int(request.args.get('page', 1))
            if request.args.get('per_page'):
                per_page = min(int(request.args.get('per_page', 50)), 1000)
            
            return {
                "page": page,
                "per_page": per_page
            }
        except ValueError:
            return {
                "page": 1,
                "per_page": 50
            }
    
    def _get_filter_params(self) -> Dict:
        """Get filter parameters from request"""
        filters = {}
        
        # Get filter parameters
        if request.args.get('agent_id'):
            filters['agent_id'] = request.args.get('agent_id')
        
        if request.args.get('domain'):
            filters['domain'] = request.args.get('domain')
        
        if request.args.get('action'):
            filters['action'] = request.args.get('action')
        
        if request.args.get('level'):
            filters['level'] = request.args.get('level')
        
        if request.args.get('since'):
            filters['since'] = request.args.get('since')
        
        if request.args.get('until'):
            filters['until'] = request.args.get('until')
        
        # Date range filters
        if request.args.get('start_date'):
            filters['start_date'] = request.args.get('start_date')
        
        if request.args.get('end_date'):
            filters['end_date'] = request.args.get('end_date')
        
        return filters
    
    def receive_logs(self):
        """Receive logs from agents"""
        try:
            data = self._validate_json_request(['logs'])
            
            # Get agent info from headers or request
            agent_id = request.headers.get('X-Agent-ID') or data.get('agent_id')
            
            # Call service method
            result = self.service.receive_logs(data, agent_id)
            
            if result["success"]:
                return jsonify(result), 200
            else:
                return jsonify(result), 400
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error receiving logs: {e}")
            return self._error_response("Failed to store logs", 500)
    
    def receive_logs_agent(self):
        """Receive logs from agent - duplicate endpoint for compatibility"""
        return self.receive_logs()
    
    def get_logs(self):
        """Retrieve logs with filtering"""
        try:
            # ✅ FIX: Get correct pagination and filter parameters
            pagination = self._get_pagination_params()
            filters = self._get_filter_params()
            
            self.logger.debug(f"Get logs request - page: {pagination['page']}, per_page: {pagination['per_page']}, filters: {filters}")
            
            # ✅ FIX: Call service method with correct parameters
            result = self.service.get_logs(
                filters=filters,
                page=pagination['page'],
                per_page=pagination['per_page']
            )
            
            # ✅ ADD: Ensure success field for frontend
            if 'success' not in result:
                result['success'] = True
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error retrieving logs: {e}")
            return jsonify({
                "success": False,
                "error": "Failed to retrieve logs",
                "logs": [],
                "total": 0,
                "page": 1,
                "per_page": 50,
                "pages": 0,
                "timezone": "UTC+7"
            }), 500
    
    def get_logs_summary(self):
        """Get logs summary statistics"""
        try:
            period = request.args.get('period', 'day').lower()
            
            # Call service method
            summary = self.service.get_logs_summary(period)
            
            # ✅ ADD: Ensure success field
            summary['success'] = True
            
            return jsonify(summary), 200
            
        except Exception as e:
            self.logger.error(f"Error generating logs summary: {e}")
            return jsonify({
                "success": False,
                "error": "Failed to generate logs summary",
                "timezone": "UTC+7"
            }), 500
    
    def delete_log(self, log_id: str):
        """Delete specific log"""
        try:
            # Call service method
            success = self.service.delete_log(log_id)
            
            if success:
                return self._success_response(message="Log deleted successfully")
            else:
                return self._error_response("Log not found", 404)
            
        except Exception as e:
            self.logger.error(f"Error deleting log {log_id}: {e}")
            return self._error_response("Failed to delete log", 500)
    
    def clear_logs(self):
        """Clear logs by criteria"""
        try:
            data = self._validate_json_request()
            
            # Call service method
            deleted_count = self.service.clear_logs(data)
            
            return jsonify({
                "success": True,
                "message": f"Cleared {deleted_count} logs",
                "deleted_count": deleted_count,
                "timezone": "UTC+7"
            }), 200
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            return self._error_response("Failed to clear logs", 500)
    
    def clear_all_logs(self):
        """Clear all logs (DELETE /api/logs)"""
        try:
            # Call service method to clear all logs
            deleted_count = self.service.clear_logs()
            
            return jsonify({
                "success": True,
                "message": f"Cleared {deleted_count} logs",
                "deleted_count": deleted_count,
                "timezone": "UTC+7"
            }), 200
            
        except Exception as e:
            self.logger.error(f"Error clearing all logs: {e}")
            return self._error_response("Failed to clear all logs", 500)
    
    def get_timezone_info(self):
        """Get server timezone information"""
        try:
            current_time = self.service._now_local()
            
            return jsonify({
                "success": True,
                "timezone": "UTC+7",
                "timezone_name": "Asia/Ho_Chi_Minh", 
                "current_time": current_time.isoformat(),
                "display_time": current_time.strftime('%Y-%m-%d %H:%M:%S'),
                "utc_offset": "+07:00"
            }), 200
            
        except Exception as e:
            self.logger.error(f"Error getting timezone info: {e}")
            return jsonify({
                "success": False,
                "error": "Failed to get timezone info",
                "timezone": "UTC+7"
            }), 500