"""
Agent Controller - handles agent HTTP requests
"""

import logging
from datetime import datetime
from flask import Blueprint, request, jsonify
from typing import Dict, Tuple
from models.agent_model import AgentModel
from services.agent_service import AgentService

class AgentController:
    """Controller for agent operations"""
    
    def __init__(self, agent_model: AgentModel, agent_service: AgentService, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = agent_model
        self.service = agent_service
        self.socketio = socketio
        self.blueprint = Blueprint('agents', __name__)
        self._register_routes()
    
    def _register_routes(self):
        """Register routes for this controller"""
        self.blueprint.add_url_rule('/register', 'register_agent', self.register_agent, methods=['POST'])
        self.blueprint.add_url_rule('', 'list_agents', self.list_agents, methods=['GET'])
        self.blueprint.add_url_rule('/<agent_id>', 'get_agent', self.get_agent, methods=['GET'])
        self.blueprint.add_url_rule('/<agent_id>', 'delete_agent', self.delete_agent, methods=['DELETE'])
        self.blueprint.add_url_rule('/<agent_id>/command', 'send_command', self.send_command, methods=['POST'])
        self.blueprint.add_url_rule('/commands', 'get_commands', self.get_commands, methods=['GET'])
        self.blueprint.add_url_rule('/command/result', 'update_command_result', self.update_command_result, methods=['POST'])
    
    def _success_response(self, data=None, message="Success", status_code=200) -> Tuple:
        """Helper method for success responses"""
        response = {"success": True, "message": message}
        if data is not None:
            response["data"] = data
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
            limit = min(int(request.args.get('limit', 50)), 1000)
            skip = int(request.args.get('skip', 0))
            page = int(request.args.get('page', 1))
            
            if 'page' in request.args:
                skip = (page - 1) * limit
            
            return {"limit": limit, "skip": skip, "page": page}
        except ValueError:
            return {"limit": 50, "skip": 0, "page": 1}
    
    def _get_filter_params(self, allowed_filters=None) -> Dict:
        """Get filter parameters"""
        filters = {}
        allowed_filters = allowed_filters or []
        
        for key, value in request.args.items():
            if key in allowed_filters and value:
                filters[key] = value
        
        return filters
    
    def register_agent(self):
        """Register a new agent"""
        try:
            data = self._validate_json_request(['hostname'])
            client_ip = request.remote_addr or data.get("ip_address", "unknown")
            
            # Call service method
            result = self.service.register_agent(data, client_ip)
            
            # Broadcast notification via SocketIO
            if self.socketio:
                self.socketio.emit("agent_registered", {
                    "agent_id": result["agent_id"],
                    "user_id": result["user_id"],
                    "hostname": data.get("hostname"),
                    "ip_address": data.get("ip_address"),
                    "status": "active",
                    "timestamp": result["server_time"]
                })
            
            return self._success_response(result, "Agent registered successfully")
            
        except ValueError as e:
            return self._error_response(str(e), 400)
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            return self._error_response("Failed to register agent", 500)
    
    def heartbeat(self):
        """Process agent heartbeat"""
        try:
            data = self._validate_json_request(['agent_id', 'token'])
            client_ip = request.remote_addr
            
            # Call service method
            result = self.service.process_heartbeat(
                data['agent_id'], 
                data['token'], 
                data, 
                client_ip
            )
            
            # Broadcast heartbeat via SocketIO
            if self.socketio:
                self.socketio.emit("agent_heartbeat", {
                    "agent_id": data['agent_id'],
                    "user_id": client_ip,
                    "status": data.get("status", "active"),
                    "timestamp": result["server_time"]
                })
            
            return self._success_response(result)
            
        except ValueError as e:
            status_code = 401 if "Invalid token" in str(e) else 400
            return self._error_response(str(e), status_code)
        except Exception as e:
            self.logger.error(f"Error processing heartbeat: {e}")
            return self._error_response("Failed to process heartbeat", 500)
    
    def list_agents(self):
        """List all agents with filtering"""
        try:
            # Get pagination and filters from request
            pagination = self._get_pagination_params()
            filters = self._get_filter_params(['status', 'hostname'])
            
            # Call service method
            result = self.service.get_agents(
                filters=filters,
                limit=pagination['limit'],
                skip=pagination['skip']
            )
            
            # Add pagination info
            result['pagination'] = {
                "total": result['total'],
                "limit": pagination['limit'],
                "skip": pagination['skip'],
                "page": pagination['page']
            }
            
            return jsonify(result), 200
            
        except Exception as e:
            self.logger.error(f"Error listing agents: {e}")
            return self._error_response("Failed to list agents", 500)
    
    def get_agent(self, agent_id: str):
        """Get detailed agent information"""
        try:
            # Call service method
            agent_data = self.service.get_agent_details(agent_id)
            return self._success_response(agent_data)
            
        except ValueError as e:
            return self._error_response(str(e), 404)
        except Exception as e:
            self.logger.error(f"Error retrieving agent: {e}")
            return self._error_response("Failed to retrieve agent details", 500)
    
    def delete_agent(self, agent_id: str):
        """Delete an agent"""
        try:
            # Get agent info before deletion for notification
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                return self._error_response("Agent not found", 404)
            
            # Call service method
            success = self.service.delete_agent(agent_id)
            if not success:
                return self._error_response("Failed to delete agent", 500)
            
            # Broadcast deletion via SocketIO
            if self.socketio:
                self.socketio.emit("agent_deleted", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            return self._success_response(message=f"Agent {agent_id} deleted successfully")
            
        except ValueError as e:
            return self._error_response(str(e), 404)
        except Exception as e:
            self.logger.error(f"Error deleting agent: {e}")
            return self._error_response("Failed to delete agent", 500)
    
    def send_command(self, agent_id: str):
        """Send command to specific agent"""
        try:
            data = self._validate_json_request(['command_type'])
            
            # Call service method
            command_id = self.service.send_command(agent_id, data, "admin")
            
            # Broadcast command creation via SocketIO
            if self.socketio:
                agent = self.model.find_by_agent_id(agent_id)
                self.socketio.emit("command_created", {
                    "command_id": command_id,
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname") if agent else "Unknown",
                    "command_type": data["command_type"],
                    "created_by": "admin",
                    "created_at": datetime.utcnow().isoformat()
                })
            
            return self._success_response({
                "command_id": command_id
            }, "Command sent to agent", 201)
            
        except ValueError as e:
            status_code = 404 if "not found" in str(e) else 400
            return self._error_response(str(e), status_code)
        except Exception as e:
            self.logger.error(f"Error sending command: {e}")
            return self._error_response("Failed to send command to agent", 500)
    
    def get_commands(self):
        """Get commands for agent (agent endpoint)"""
        try:
            agent_id = request.args.get('agent_id')
            token = request.args.get('token')
            
            if not agent_id or not token:
                return self._error_response("Agent ID and token are required", 400)
            
            # Call service method
            commands = self.service.get_pending_commands(agent_id, token)
            
            return self._success_response(commands)
            
        except ValueError as e:
            status_code = 404 if "not found" in str(e) else 401 if "token" in str(e) else 400
            return self._error_response(str(e), status_code)
        except Exception as e:
            self.logger.error(f"Error getting commands: {e}")
            return self._error_response("Failed to retrieve commands", 500)
    
    def list_commands(self):
        """List commands (admin endpoint)"""
        try:
            # Get filters and pagination
            agent_id = request.args.get('agent_id')
            status = request.args.get('status')
            command_type = request.args.get('command_type')
            pagination = self._get_pagination_params()
            
            filters = {}
            if agent_id:
                filters["agent_id"] = agent_id
            if status:
                filters["status"] = status
            if command_type:
                filters["command_type"] = command_type
            
            # Call service method
            result = self.service.list_commands(
                filters=filters,
                limit=pagination['limit'],
                skip=pagination['skip']
            )
            
            # Add pagination info
            result['pagination'] = {
                "total": result['total'],
                "limit": pagination['limit'],
                "skip": pagination['skip'],
                "page": pagination['page']
            }
            
            return self._success_response(result)
            
        except Exception as e:
            self.logger.error(f"Error listing commands: {e}")
            return self._error_response("Failed to list commands", 500)
    
    def update_command_result(self):
        """Update command execution result"""
        try:
            data = self._validate_json_request(['agent_id', 'token', 'command_id', 'status'])
            
            # Call service method
            self.service.update_command_result(
                data['agent_id'],
                data['token'],
                data['command_id'],
                data['status'],
                data.get('result'),
                data.get('execution_time')
            )
            
            # Broadcast update via SocketIO
            if self.socketio:
                agent = self.model.find_by_agent_id(data['agent_id'])
                self.socketio.emit("command_status_update", {
                    "command_id": data['command_id'],
                    "agent_id": data['agent_id'],
                    "hostname": agent.get("hostname") if agent else "Unknown",
                    "status": data["status"],
                    "completed_at": datetime.utcnow().isoformat()
                })
            
            return self._success_response(message="Command result updated")
            
        except ValueError as e:
            status_code = 404 if "not found" in str(e) else 401 if "token" in str(e) else 400
            return self._error_response(str(e), status_code)
        except Exception as e:
            self.logger.error(f"Error updating command result: {e}")
            return self._error_response("Failed to update command result", 500)