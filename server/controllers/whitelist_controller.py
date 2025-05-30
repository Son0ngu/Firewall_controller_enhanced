"""
Whitelist Controller - handles whitelist HTTP requests
"""

import logging
from flask import Blueprint, request, jsonify
from typing import Dict, Tuple
from models.whitelist_model import WhitelistModel
from services.whitelist_service import WhitelistService
from datetime import datetime

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
        # GET /api/whitelist - List all entries
        self.blueprint.add_url_rule('/whitelist', 
                                   methods=['GET'], 
                                   view_func=self.list_whitelist)
        
        # POST /api/whitelist - Add new entry
        self.blueprint.add_url_rule('/whitelist', 
                                   methods=['POST'], 
                                   view_func=self.add_entry)
        
        # PUT /api/whitelist/<entry_id> - Update entry
        self.blueprint.add_url_rule('/whitelist/<entry_id>', 
                                   methods=['PUT'], 
                                   view_func=self.update_entry)
        
        # DELETE /api/whitelist/<entry_id> - Delete entry
        self.blueprint.add_url_rule('/whitelist/<entry_id>', 
                                   methods=['DELETE'], 
                                   view_func=self.delete_entry)
        
        # Other routes...
        self.blueprint.add_url_rule('/whitelist/test', 
                                   methods=['POST'], 
                                   view_func=self.test_entry)
        
        self.blueprint.add_url_rule('/whitelist/dns-test', 
                                   methods=['POST'], 
                                   view_func=self.dns_test)
        
        self.blueprint.add_url_rule('/whitelist/agent-sync', 
                                   methods=['GET'], 
                                   view_func=self.agent_sync)
        
        self.blueprint.add_url_rule('/whitelist/bulk', 
                                   methods=['POST'], 
                                   view_func=self.bulk_add)
        
        self.blueprint.add_url_rule('/whitelist/statistics', 
                                   methods=['GET'], 
                                   view_func=self.get_statistics)
    
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
            
            self.logger.debug(f"List whitelist request with filters: {filters}")
            
            # Call service method
            result = self.service.get_all_entries(filters)
            
            self.logger.debug(f"Returning {len(result.get('domains', []))} entries")
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error listing whitelist: {str(e)}", exc_info=True)
            return self._error_response("Failed to list whitelist", 500)
    
    def add_entry(self):
        """Add new entry to whitelist"""
        try:
            data = self._validate_json_request(['value'])
            client_ip = request.remote_addr
            
            self.logger.info(f"Adding entry request: {data} from {client_ip}")
            
            # Call service method
            result = self.service.add_entry(data, client_ip)
            
            self.logger.info(f"Entry added successfully: {result}")
            
            return self._success_response(result, result["message"], 201)
            
        except ValueError as e:
            self.logger.warning(f"Validation error: {e}")
            status_code = 409 if "already exists" in str(e) else 400
            return self._error_response(str(e), status_code)
        except Exception as e:
            self.logger.error(f"Error adding entry: {str(e)}", exc_info=True)
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
            
            self.logger.debug(f"Agent sync request - since: {since}, agent_id: {agent_id}")
            
            # ✅ FIX: Better parameter validation
            since_datetime = None
            if since:
                try:
                    since_datetime = datetime.fromisoformat(since.replace('Z', '+00:00'))
                except ValueError as e:
                    self.logger.warning(f"Invalid since parameter: {since}, error: {e}")
                    # Continue without since filter
            
            # Call service method
            result = self.service.get_agent_sync_data(since_datetime, agent_id)
            
            # ✅ FIX: Ensure response format is correct
            if not isinstance(result, dict):
                result = {"domains": [], "error": "Invalid response format"}
            
            if "domains" not in result:
                result["domains"] = []
            
            # Add success indicator
            result["success"] = True
            result["agent_id"] = agent_id
            
            self.logger.debug(f"Returning {len(result.get('domains', []))} domains for agent sync")
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error in agent sync: {str(e)}", exc_info=True)
            
            # ✅ FIX: Always return valid JSON with domains array
            error_response = {
                "success": False,
                "error": "Sync failed: " + str(e),
                "domains": [],  # Always include empty domains array
                "timestamp": datetime.now().isoformat(),
                "count": 0,
                "type": "error"
            }
            
            return jsonify(error_response), 500
    
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
    
    def update_entry(self, entry_id: str):
        """Update an entry"""
        try:
            data = self._validate_json_request()
            
            # Call service method to update entry
            success = self.service.update_entry(entry_id, data)
            
            if success:
                return self._success_response(message="Entry updated successfully")
            else:
                return self._error_response("Failed to update entry", 500)
                
        except ValueError as e:
            return self._error_response(str(e), 404)
        except Exception as e:
            self.logger.error(f"Error updating entry: {str(e)}")
            return self._error_response("Failed to update entry", 500)