"""
Whitelist Controller - handles whitelist HTTP requests
vietnam ONLY - Clean and simple
"""

import logging
from flask import Blueprint, request, jsonify
from typing import Dict, Tuple
from models.whitelist_model import WhitelistModel
from services.whitelist_service import WhitelistService

# Import time utilities - vietnam ONLY
from time_utils import now_iso, parse_agent_timestamp

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
        """Register all whitelist routes"""
        
        # Agent sync endpoint - MOST IMPORTANT
        self.blueprint.add_url_rule('/whitelist/agent-sync', 
                                   methods=['GET'], 
                                   view_func=self.agent_sync)
        
        # Admin management endpoints
        self.blueprint.add_url_rule('/whitelist', 
                                   methods=['GET'], 
                                   view_func=self.list_domains)
        
        self.blueprint.add_url_rule('/whitelist', 
                                   methods=['POST'], 
                                   view_func=self.add_domain)
        
        self.blueprint.add_url_rule('/whitelist/<domain_id>', 
                                   methods=['DELETE'], 
                                   view_func=self.delete_domain)
        
        self.blueprint.add_url_rule('/whitelist/import', 
                                   methods=['POST'], 
                                   view_func=self.import_domains)
        
        self.blueprint.add_url_rule('/whitelist/export', 
                                   methods=['GET'], 
                                   view_func=self.export_domains)
        
        self.blueprint.add_url_rule('/whitelist/statistics', 
                                   methods=['GET'], 
                                   view_func=self.get_statistics)
        
        # Bulk operations - NEW ROUTES
        self.blueprint.add_url_rule('/whitelist/bulk', 
                                   methods=['POST'], 
                                   view_func=self.bulk_add_entries)
        
        self.blueprint.add_url_rule('/whitelist/bulk-update', 
                                   methods=['POST'], 
                                   view_func=self.bulk_update_entries)
        
        self.blueprint.add_url_rule('/whitelist/bulk-delete', 
                                   methods=['POST'], 
                                   view_func=self.bulk_delete_entries)
    
    def agent_sync(self):
        """Sync whitelist for agents - vietnam ONLY"""
        try:
            # Get query parameters
            since = request.args.get('since')
            agent_id = request.args.get('agent_id')
            
            self.logger.debug(f"Agent sync request - since: {since}, agent_id: {agent_id}")
            
            # FIX: Better parameter validation using time_utils - vietnam ONLY
            since_datetime = None
            if since:
                try:
                    since_datetime = parse_agent_timestamp(since)  # vietnam parsing
                except Exception as e:
                    self.logger.warning(f"Invalid since parameter: {since}, error: {e}")
                    # Continue without since filter
            
            # Call service method
            result = self.service.get_agent_sync_data(since_datetime, agent_id)
            
            # FIX: Ensure response format is correct
            if not isinstance(result, dict):
                result = {"domains": [], "error": "Invalid response format"}
            
            if "domains" not in result:
                result["domains"] = []
            
            # Add success indicator and timestamp - vietnam ONLY
            result["success"] = True
            result["agent_id"] = agent_id
            result["timestamp"] = now_iso()  # vietnam ISO
            result["count"] = len(result.get("domains", []))
            
            self.logger.debug(f"Returning {len(result.get('domains', []))} domains for agent sync")
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error in agent sync: {str(e)}", exc_info=True)
            
            # FIX: Always return valid JSON with domains array - vietnam ONLY
            error_response = {
                "success": False,
                "error": "Sync failed: " + str(e),
                "domains": [],  # Always include empty domains array
                "timestamp": now_iso(),  # vietnam ISO
                "count": 0,
                "type": "error"
            }
            
            return jsonify(error_response), 500
    
    def list_domains(self):
        """List all whitelist domains - vietnam ONLY"""
        try:
            # Get pagination parameters
            limit = min(int(request.args.get('limit', 100)), 1000)
            offset = int(request.args.get('offset', 0))
            search = request.args.get('search', '').strip()
            
            # Call service method
            result = self.service.get_all_domains(limit, offset, search)
            
            # Add vietnam timestamp to response
            if isinstance(result, dict):
                result["timestamp"] = now_iso()  # vietnam ISO
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error listing domains: {e}")
            return self._error_response("Failed to list domains", 500)
    
    def add_domain(self):
        """Add new domain to whitelist - vietnam ONLY"""
        try:
            if not request.is_json:
                return self._error_response("Request must be JSON", 400)
            
            data = request.get_json()
            if not data or 'value' not in data:
                return self._error_response("Domain value is required", 400)
            
            domain_value = data['value'].strip().lower()
            if not domain_value:
                return self._error_response("Domain value cannot be empty", 400)
            
            # Call service method
            result = self.service.add_domain(domain_value, data.get('category', 'general'))
            
            # Broadcast update via SocketIO - vietnam ONLY
            if self.socketio and result.get('success'):
                self.socketio.emit('whitelist_updated', {
                    'action': 'added',
                    'domain': domain_value,
                    'category': data.get('category', 'general'),
                    'timestamp': now_iso()  # vietnam ISO
                })
            
            # Add vietnam timestamp to response
            if isinstance(result, dict):
                result["timestamp"] = now_iso()  # vietnam ISO
            
            return jsonify(result), 201 if result.get('success') else 400
            
        except Exception as e:
            self.logger.error(f"Error adding domain: {e}")
            return self._error_response("Failed to add domain", 500)
    
    def delete_domain(self, domain_id: str):
        """Delete domain from whitelist - vietnam ONLY"""
        try:
            # Call service method
            result = self.service.delete_domain(domain_id)
            
            # Broadcast update via SocketIO - vietnam ONLY
            if self.socketio and result.get('success'):
                self.socketio.emit('whitelist_updated', {
                    'action': 'deleted',
                    'domain_id': domain_id,
                    'timestamp': now_iso()  # vietnam ISO
                })
            
            # Add vietnam timestamp to response
            if isinstance(result, dict):
                result["timestamp"] = now_iso()  # vietnam ISO
            
            return jsonify(result), 200 if result.get('success') else 404
            
        except Exception as e:
            self.logger.error(f"Error deleting domain {domain_id}: {e}")
            return self._error_response("Failed to delete domain", 500)
    
    def import_domains(self):
        """Import multiple domains - vietnam ONLY"""
        try:
            if not request.is_json:
                return self._error_response("Request must be JSON", 400)
            
            data = request.get_json()
            if not data or 'domains' not in data:
                return self._error_response("Domains list is required", 400)
            
            domains = data['domains']
            if not isinstance(domains, list):
                return self._error_response("Domains must be a list", 400)
            
            # Call service method
            result = self.service.import_domains(domains, data.get('category', 'imported'))
            
            # Broadcast update via SocketIO - vietnam ONLY
            if self.socketio and result.get('success'):
                self.socketio.emit('whitelist_updated', {
                    'action': 'imported',
                    'count': result.get('added_count', 0),
                    'category': data.get('category', 'imported'),
                    'timestamp': now_iso()  # vietnam ISO
                })
            
            # Add vietnam timestamp to response
            if isinstance(result, dict):
                result["timestamp"] = now_iso()  # vietnam ISO
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error importing domains: {e}")
            return self._error_response("Failed to import domains", 500)
    
    def export_domains(self):
        """Export whitelist domains - vietnam ONLY"""
        try:
            format = request.args.get('format', 'json')
            category = request.args.get('category')
            
            # Call service method
            result = self.service.export_domains(format, category)
            
            if result.get('success'):
                # Add vietnam timestamp to response
                if isinstance(result, dict):
                    result["timestamp"] = now_iso()  # vietnam ISO
                
                if format == 'txt':
                    from flask import Response
                    return Response(
                        result['data'],
                        mimetype='text/plain',
                        headers={'Content-Disposition': 'attachment; filename=whitelist.txt'}
                    )
                else:
                    return jsonify(result), 200
            else:
                return self._error_response(result.get('error', 'Export failed'), 500)
                
        except Exception as e:
            self.logger.error(f"Error exporting domains: {e}")
            return self._error_response("Failed to export domains", 500)
    
    def get_statistics(self):
        """Get whitelist statistics - vietnam ONLY"""
        try:
            # Call service method
            stats = self.service.get_statistics()
            
            return jsonify({
                'success': True,
                'statistics': stats,
                'timestamp': now_iso()  # vietnam ISO
            }), 200
            
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return self._error_response("Failed to get statistics", 500)
    
    def bulk_add_entries(self):
        """Bulk add multiple whitelist entries"""
        try:
            data = request.get_json()
            
            if not data or 'items' not in data:
                return jsonify({
                    "success": False,
                    "error": "No items provided"
                }), 400
            
            items = data['items']
            
            if not isinstance(items, list):
                return jsonify({
                    "success": False,
                    "error": "Items must be an array"
                }), 400
            
            if len(items) == 0:
                return jsonify({
                    "success": False,
                    "error": "No items to import"
                }), 400
            
            if len(items) > 1000:
                return jsonify({
                    "success": False,
                    "error": "Maximum 1000 items per bulk operation"
                }), 400
            
            # Get client IP
            client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
            if ',' in client_ip:
                client_ip = client_ip.split(',')[0].strip()
            
            # Process bulk add
            result = self.service.bulk_add_entries(items, client_ip)
            
            return jsonify(result), 200 if result['success'] else 400
            
        except Exception as e:
            self.logger.error(f"Error in bulk add: {e}")
            return jsonify({
                "success": False,
                "error": str(e),
                "server_time": now_iso()
            }), 500
    
    def bulk_update_entries(self):
        """Bulk update multiple whitelist entries"""
        try:
            data = request.get_json()
            
            if not data or 'item_ids' not in data:
                return jsonify({
                    "success": False,
                    "error": "No item IDs provided"
                }), 400
            
            item_ids = data['item_ids']
            active = data.get('active', True)
            
            if not isinstance(item_ids, list):
                return jsonify({
                    "success": False,
                    "error": "Item IDs must be an array"
                }), 400
            
            updated_count = 0
            errors = []
            
            for item_id in item_ids:
                try:
                    success = self.service.update_entry(item_id, {"is_active": active})
                    if success:
                        updated_count += 1
                    else:
                        errors.append(f"Failed to update {item_id}")
                except Exception as e:
                    errors.append(f"Error updating {item_id}: {str(e)}")
            
            return jsonify({
                "success": True,
                "updated_count": updated_count,
                "error_count": len(errors),
                "errors": errors[:10],  # Limit error list
                "server_time": now_iso()
            }), 200
            
        except Exception as e:
            self.logger.error(f"Error in bulk update: {e}")
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
    
    def bulk_delete_entries(self):
        """Bulk delete multiple whitelist entries"""
        try:
            data = request.get_json()
            
            if not data or 'item_ids' not in data:
                return jsonify({
                    "success": False,
                    "error": "No item IDs provided"
                }), 400
            
            item_ids = data['item_ids']
            
            if not isinstance(item_ids, list):
                return jsonify({
                    "success": False,
                    "error": "Item IDs must be an array"
                }), 400
            
            deleted_count = 0
            errors = []
            
            for item_id in item_ids:
                try:
                    success = self.service.delete_entry(item_id)
                    if success:
                        deleted_count += 1
                    else:
                        errors.append(f"Failed to delete {item_id}")
                except Exception as e:
                    errors.append(f"Error deleting {item_id}: {str(e)}")
            
            return jsonify({
                "success": True,
                "deleted_count": deleted_count,
                "error_count": len(errors),
                "errors": errors[:10],
                "server_time": now_iso()
            }), 200
            
        except Exception as e:
            self.logger.error(f"Error in bulk delete: {e}")
            return jsonify({
                "success": False,
                "error": str(e)
            }), 500
    
    def _error_response(self, message: str, status_code: int) -> Tuple:
        """Create error response - vietnam ONLY"""
        return jsonify({
            "success": False,
            "error": message,
            "timestamp": now_iso()  # vietnam ISO
        }), status_code