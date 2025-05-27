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
        """Get pagination parameters"""
        try:
            limit = min(int(request.args.get('limit', 100)), 1000)
            skip = int(request.args.get('skip', 0))
            sort_field = request.args.get('sort', 'timestamp')
            sort_order = request.args.get('order', 'desc')
            
            return {
                "limit": limit,
                "skip": skip,
                "sort_field": sort_field,
                "sort_order": sort_order
            }
        except ValueError:
            return {
                "limit": 100,
                "skip": 0,
                "sort_field": "timestamp",
                "sort_order": "desc"
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
        
        if request.args.get('since'):
            filters['since'] = request.args.get('since')
        
        if request.args.get('until'):
            filters['until'] = request.args.get('until')
        
        return filters
    
    def receive_logs(self):
        """Receive logs from agents"""
        try:
            data = self._validate_json_request(['logs'])
            
            # Call service method
            result = self.service.receive_logs(data)
            
            status_code = 201 if result["status"] == "success" else 200
            return self._success_response(result, result["message"], status_code)
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error receiving logs: {e}")
            return self._error_response("Failed to store logs", 500)
    
    def get_logs(self):
        """Retrieve logs with filtering"""
        try:
            # Get pagination and filter parameters
            pagination = self._get_pagination_params()
            filters = self._get_filter_params()
            
            # Call service method
            result = self.service.get_logs(
                filters=filters,
                limit=pagination['limit'],
                skip=pagination['skip'],
                sort_field=pagination['sort_field'],
                sort_order=pagination['sort_order']
            )
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error retrieving logs: {e}")
            return self._error_response("Failed to retrieve logs", 500)
    
    def get_logs_summary(self):
        """Get logs summary statistics"""
        try:
            period = request.args.get('period', 'day').lower()
            
            # Call service method
            summary = self.service.get_logs_summary(period)
            
            return jsonify(summary), 200
            
        except Exception as e:
            self.logger.error(f"Error generating logs summary: {e}")
            return self._error_response("Failed to generate logs summary", 500)
    
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
            result = self.service.clear_logs(data)
            
            return self._success_response(result, result["message"])
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error clearing logs: {e}")
            return self._error_response("Failed to clear logs", 500)
    
    def clear_all_logs(self):
        """Clear all logs (DELETE /api/logs)"""
        try:
            # Call service method to clear all logs
            result = self.service.clear_logs({"clear_all": True})
            
            return self._success_response(result, result["message"])
            
        except Exception as e:
            self.logger.error(f"Error clearing all logs: {e}")
            return self._error_response("Failed to clear all logs", 500)