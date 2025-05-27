"""
Whitelist Controller - handles whitelist HTTP requests
"""

import logging
from flask import Blueprint, request, jsonify
from typing import Dict, Tuple
from models.whitelist_model import WhitelistModel
from services.whitelist_service import WhitelistService

class WhitelistController:
    """Controller for whitelist operations"""
    
    def __init__(self, whitelist_model: WhitelistModel, whitelist_service: WhitelistService, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = whitelist_model
        self.service = whitelist_service
        self.socketio = socketio
        self.blueprint = Blueprint('whitelist', __name__)
        self._register_routes()
    
    def _register_routes(self):
        """Register routes for this controller"""
        self.blueprint.add_url_rule('', 'list_whitelist', self.list_whitelist, methods=['GET'])
        self.blueprint.add_url_rule('', 'add_entry', self.add_entry, methods=['POST'])
        self.blueprint.add_url_rule('/test', 'test_entry', self.test_entry, methods=['POST'])
        self.blueprint.add_url_rule('/dns-test', 'dns_test', self.dns_test, methods=['POST'])
        self.blueprint.add_url_rule('/agent-sync', 'agent_sync', self.agent_sync, methods=['GET'])
        self.blueprint.add_url_rule('/bulk', 'bulk_add', self.bulk_add, methods=['POST'])
        self.blueprint.add_url_rule('/<entry_id>', 'delete_entry', self.delete_entry, methods=['DELETE'])
        self.blueprint.add_url_rule('/statistics', 'get_statistics', self.get_statistics, methods=['GET'])
    
    def _success_response(self, data=None, message="Success", status_code=200) -> Tuple:
        """Helper method for success responses"""
        if isinstance(data, dict) and "domains" in data:
            # For backward compatibility, return the data structure as-is
            return jsonify(data), status_code
        
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
    
    def _get_filter_params(self) -> Dict:
        """Get filter parameters from request"""
        filters = {}
        
        # Get filter parameters
        if request.args.get('type'):
            filters['type'] = request.args.get('type')
        
        if request.args.get('category'):
            filters['category'] = request.args.get('category')
        
        if request.args.get('search'):
            filters['search'] = request.args.get('search')
        
        if request.args.get('added_by'):
            filters['added_by'] = request.args.get('added_by')
        
        return filters
    
    def list_whitelist(self):
        """Get all whitelist entries"""
        try:
            # Get filter parameters
            filters = self._get_filter_params()
            
            # Call service method
            result = self.service.get_all_entries(filters)
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error listing whitelist: {str(e)}")
            return self._error_response("Failed to list whitelist", 500)
    
    def add_entry(self):
        """Add new entry to whitelist"""
        try:
            data = self._validate_json_request(['value'])
            client_ip = request.remote_addr
            
            # Call service method
            result = self.service.add_entry(data, client_ip)
            
            return self._success_response(result, result["message"], 201)
            
        except ValueError as e:
            status_code = 409 if "already exists" in str(e) else 400
            return self._error_response(str(e), status_code)
        except Exception as e:
            self.logger.error(f"Error adding entry: {str(e)}")
            return self._error_response("Failed to add entry", 500)
    
    def test_entry(self):
        """Test an entry before adding it"""
        try:
            data = self._validate_json_request(['type', 'value'])
            
            # Call service method
            result = self.service.test_entry(data)
            
            return jsonify(result), 200
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error testing entry: {str(e)}")
            return self._error_response("Test failed", 500)
    
    def dns_test(self):
        """Test DNS resolution for a domain"""
        try:
            data = self._validate_json_request(['domain'])
            domain = data.get("domain", "").strip()
            
            # Call service method
            result = self.service.test_dns(domain)
            
            return jsonify(result), 200
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error testing DNS: {str(e)}")
            return self._error_response("DNS test failed", 500)
    
    def agent_sync(self):
        """Sync whitelist for agents"""
        try:
            # Get query parameters
            since = request.args.get('since')
            agent_id = request.args.get('agent_id')
            
            # Call service method
            result = self.service.get_agent_sync_data(since, agent_id)
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error in agent sync: {str(e)}")
            return jsonify({"error": "Sync failed", "domains": []}), 500
    
    def bulk_add(self):
        """Bulk add entries to whitelist"""
        try:
            data = self._validate_json_request(['entries'])
            client_ip = request.remote_addr
            
            entries = data.get('entries', [])
            if not isinstance(entries, list):
                raise ValueError("'entries' must be an array")
            
            # Call service method
            result = self.service.bulk_add_entries(entries, client_ip)
            
            status_code = 201 if result["success"] else 400
            return self._success_response(result, "Bulk operation completed", status_code)
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error in bulk add: {str(e)}")
            return self._error_response("Failed to bulk add entries", 500)
    
    def delete_entry(self, entry_id: str):
        """Delete an entry"""
        try:
            # Call service method
            success = self.service.delete_entry(entry_id)
            
            if success:
                return self._success_response(message="Entry deleted successfully")
            else:
                return self._error_response("Failed to delete entry", 500)
            
        except ValueError as e:
            return self._error_response(str(e), 404)
        except Exception as e:
            self.logger.error(f"Error deleting entry: {str(e)}")
            return self._error_response("Failed to delete entry", 500)
    
    def get_statistics(self):
        """Get whitelist statistics"""
        try:
            # Call service method
            stats = self.service.get_statistics()
            
            return jsonify(stats), 200
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {str(e)}")
            return self._error_response("Failed to get statistics", 500)