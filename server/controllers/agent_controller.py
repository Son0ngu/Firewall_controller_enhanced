"""
Agent Controller - handles agent HTTP requests
"""

import logging
from datetime import datetime, timezone, timedelta  # ✅ Add timedelta import
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
        
        # ✅ THÊM: Dùng cùng timezone với service
        self.server_timezone = self.service.server_timezone
        self._register_routes()
    
    def _register_routes(self):
        """Register routes for this controller"""
        # ✅ FIX: Add missing '/agents' prefix to routes
        
        # Core agent management routes
        self.blueprint.add_url_rule('/agents/register', 'register_agent', self.register_agent, methods=['POST'])
        self.blueprint.add_url_rule('/agents/heartbeat', 'heartbeat', self.heartbeat, methods=['POST'])
        self.blueprint.add_url_rule('/agents', 'list_agents', self.list_agents, methods=['GET'])  # ✅ FIX: Add this route
        self.blueprint.add_url_rule('/agents/statistics', 'get_statistics', self.get_statistics, methods=['GET'])  # ✅ FIX: Add agents prefix
        
        # Individual agent routes
        self.blueprint.add_url_rule('/agents/<agent_id>', 'get_agent', self.get_agent, methods=['GET'])
        self.blueprint.add_url_rule('/agents/<agent_id>', 'delete_agent', self.delete_agent, methods=['DELETE'])
        
        # Agent command routes
        self.blueprint.add_url_rule('/agents/<agent_id>/command', 'send_command', self.send_command, methods=['POST'])
        self.blueprint.add_url_rule('/agents/commands', 'list_commands', self.list_commands, methods=['GET'])
        self.blueprint.add_url_rule('/agents/command/result', 'update_command_result', self.update_command_result, methods=['POST'])
        self.blueprint.add_url_rule('/agents/<agent_id>/commands', 'get_agent_commands', self.get_agent_commands, methods=['GET'])
        
        # Utility routes
        self.blueprint.add_url_rule('/agents/<agent_id>/ping', 'ping_agent', self.ping_agent, methods=['POST'])
        
        # ✅ DEBUG: Add debug routes (optional - remove in production)
        self.blueprint.add_url_rule('/agents/debug/status', 'debug_status', self.debug_status, methods=['GET'])
        self.blueprint.add_url_rule('/agents/debug/direct', 'debug_direct_call', self.debug_direct_call, methods=['GET'])

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
    
    def _now_local(self) -> datetime:
        """Lấy thời gian hiện tại theo múi giờ của server"""
        return datetime.now(self.server_timezone)
    
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
            
            # ✅ IMPROVED: Enhanced SocketIO broadcast với detailed info
            if self.socketio:
                agent = self.model.find_by_agent_id(data['agent_id'])
                
                # ✅ THÊM: Calculate time since last heartbeat for broadcast
                current_time = self._now_local()
                time_since_last = 0  # Just received
                
                self.socketio.emit("agent_heartbeat", {
                    "agent_id": data['agent_id'],
                    "hostname": agent.get("hostname") if agent else "Unknown",
                    "status": "active",
                    "last_heartbeat": current_time.isoformat(),
                    "time_since_heartbeat": time_since_last,
                    "metrics": data.get("metrics", {}),
                    "client_ip": client_ip,
                    "timestamp": current_time.isoformat(),
                    "agent_version": data.get("agent_version"),
                    "platform": data.get("platform")
                })
            
            return self._success_response(result)
            
        except ValueError as e:
            status_code = 401 if "Invalid token" in str(e) else 400
            return self._error_response(str(e), status_code)
        except Exception as e:
            self.logger.error(f"Error processing heartbeat: {e}")
            return self._error_response("Failed to process heartbeat", 500)
    
    def list_agents(self):
        """List all agents with filtering - COMPLETE VERSION"""
        try:
            self.logger.info("📊 List agents called")
            
            pagination = self._get_pagination_params()
            filters = self._get_filter_params(['status', 'hostname'])
            
            agents_with_status = self.service.get_agents_with_status()
            self.logger.info(f"📊 Found {len(agents_with_status)} agents")
            
            # Apply filters
            filtered_agents = agents_with_status
            if filters.get("status"):
                status_filter = filters["status"]
                filtered_agents = [a for a in filtered_agents if a.get('status') == status_filter]
            
            if filters.get("hostname"):
                hostname_filter = filters["hostname"].lower()
                filtered_agents = [a for a in filtered_agents if hostname_filter in a.get('hostname', '').lower()]
            
            # Apply pagination
            total_count = len(filtered_agents)
            agents_list = filtered_agents[pagination['skip']:pagination['skip']+pagination['limit']]
            
            # Format for API response
            formatted_agents = []
            for agent in agents_list:
                last_heartbeat_iso = None
                if agent.get("last_heartbeat"):
                    if isinstance(agent["last_heartbeat"], str):
                        last_heartbeat_iso = agent["last_heartbeat"]
                    else:
                        last_heartbeat_iso = agent["last_heartbeat"].isoformat()
                
                registered_date_iso = None
                if agent.get("registered_date"):
                    if isinstance(agent["registered_date"], str):
                        registered_date_iso = agent["registered_date"]
                    else:
                        registered_date_iso = agent["registered_date"].isoformat()
                
                formatted_agent = {
                    "agent_id": agent.get("agent_id"),
                    "hostname": agent.get("hostname", "Unknown"),
                    "ip_address": agent.get("ip_address", "Unknown"),
                    "platform": agent.get("platform", "Unknown"),
                    "os_info": agent.get("os_info", "Unknown"),
                    "agent_version": agent.get("agent_version", "Unknown"),
                    "status": agent.get("status"),
                    "registered_date": registered_date_iso,
                    "last_heartbeat": last_heartbeat_iso,
                    "time_since_heartbeat": agent.get("time_since_heartbeat"),
                    "metrics": agent.get("metrics"),
                    "user_id": agent.get("ip_address")
                }
                
                formatted_agents.append(formatted_agent)
            
            return jsonify({
                "agents": formatted_agents,
                "total": total_count,
                "success": True,
                "pagination": {
                    "total": total_count,
                    "limit": pagination['limit'],
                    "skip": pagination['skip'],
                    "page": pagination['page']
                }
            }), 200
            
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
            # ✅ THÊM: Get agent info trước khi delete
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                return self._error_response("Agent not found", 404)
            
            # ✅ SỬA: Gọi service để delete
            success = self.service.delete_agent(agent_id)
            
            if success:
                # ✅ THÊM: Broadcast deletion qua SocketIO
                if self.socketio:
                    self.socketio.emit("agent_deleted", {
                        "agent_id": agent_id,
                        "hostname": agent.get("hostname"),
                        "timestamp": self._now_local().isoformat()
                    })
                
                return self._success_response(
                    message=f"Agent {agent.get('hostname', agent_id)} deleted successfully"
                )
            else:
                return self._error_response("Failed to delete agent", 500)
                
        except ValueError as e:
            return self._error_response(str(e), 404)
        except Exception as e:
            self.logger.error(f"Error deleting agent {agent_id}: {e}")
            return self._error_response("Internal server error", 500)

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
                    "created_at": self._now_local().isoformat()  # ✅ SỬA: Dùng local time
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
        """List all commands (admin endpoint)"""
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
    
    def get_agent_commands(self, agent_id: str):
        """Get commands for specific agent (admin endpoint)"""
        try:
            # Get filters and pagination
            status = request.args.get('status')
            pagination = self._get_pagination_params()
            
            filters = {"agent_id": agent_id}
            if status:
                filters["status"] = status
            
            # Call service method
            result = self.service.list_commands(
                filters=filters,
                limit=pagination['limit'],
                skip=pagination['skip']
            )
            
            return self._success_response(result)
            
        except Exception as e:
            self.logger.error(f"Error getting commands for agent {agent_id}: {e}")
            return self._error_response("Failed to get agent commands", 500)
    
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
                    "completed_at": self._now_local().isoformat()  # ✅ SỬA: Dùng local time
                })
            
            return self._success_response(message="Command result updated")
            
        except Exception as e:
            self.logger.error(f"Error updating command result: {e}")
            return self._error_response("Failed to update command result", 500)

    def debug_status(self):
        """Debug endpoint để kiểm tra status calculation"""
        try:
            current_time = self._now_local()
            agents = self.model.get_all_agents({}, limit=100)
            
            debug_info = {
                "server_time": current_time.isoformat(),
                "thresholds": {
                    "active": self.service.active_threshold,
                    "inactive": self.service.inactive_threshold
                },
                "agents": []
            }
            
            for agent in agents:
                last_heartbeat = agent.get("last_heartbeat")
                if last_heartbeat:
                    if last_heartbeat.tzinfo is None:
                        last_heartbeat_utc = last_heartbeat.replace(tzinfo=self.server_timezone)
                    else:
                        last_heartbeat_utc = last_heartbeat.astimezone(self.server_timezone)
                    
                    time_diff = (current_time - last_heartbeat_utc).total_seconds()
                    
                    debug_info["agents"].append({
                        "hostname": agent.get("hostname"),
                        "last_heartbeat": last_heartbeat.isoformat(),
                        "time_since_heartbeat": time_diff,
                        "status": "active" if time_diff < self.service.active_threshold else 
                                 "inactive" if time_diff < self.service.inactive_threshold else "offline"
                    })
            
            return self._success_response(debug_info)
            
        except Exception as e:
            self.logger.error(f"Error in debug status: {e}")
            return self._error_response("Debug failed", 500)

    def get_statistics(self):
        """Get agent statistics"""
        try:
            # ✅ CRITICAL: Use calculate_statistics method
            stats = self.service.calculate_statistics()
            self.logger.info(f"📊 Statistics calculated: {stats}")
            return self._success_response(stats)
        except Exception as e:
            self.logger.error(f"Error getting statistics: {e}")
            return self._error_response("Failed to get statistics", 500)

    def debug_direct_call(self):
        """Debug endpoint - direct service call"""
        try:
            self.logger.info("🔧 DEBUG: Direct get_agents_with_status call")
            
            # Call service method directly
            agents = self.service.get_agents_with_status()
            
            debug_data = []
            for agent in agents:
                debug_data.append({
                    'hostname': agent.get('hostname'),
                    'last_heartbeat': agent.get('last_heartbeat'),
                    'last_heartbeat_type': str(type(agent.get('last_heartbeat'))),
                    'status': agent.get('status'),
                    'time_since_heartbeat': agent.get('time_since_heartbeat'),
                    'calculated_directly': True
                })
            
            return jsonify({
                'success': True,
                'method_used': 'get_agents_with_status (direct)',
                'total': len(agents),
                'debug_data': debug_data
            })
            
        except Exception as e:
            self.logger.error(f"Debug direct call error: {e}")
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    # Add method:
    def debug_timezone_issue(self):
        """Debug timezone calculation issue"""
        try:
            debug_result = self.service.debug_timezone_issue()
            return jsonify({
                'success': True,
                'debug_data': debug_result
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            }), 500

    def ping_agent(self, agent_id: str):
        """Ping agent to check connectivity"""
        try:
            self.logger.info(f"📡 Ping request for agent: {agent_id}")
            
            # Call service method
            result = self.service.ping_agent(agent_id)
            
            # Broadcast ping result via SocketIO
            if self.socketio:
                agent = self.model.find_by_agent_id(agent_id)
                self.socketio.emit("agent_ping_result", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname") if agent else "Unknown",
                    "ping_successful": result.get("success", False),
                    "response_time": result.get("response_time"),
                    "timestamp": self._now_local().isoformat()
                })
            
            if result.get("success"):
                return self._success_response(result, "Agent ping successful")
            else:
                return self._error_response(result.get("error", "Ping failed"), 408)
        
        except ValueError as e:
            return self._error_response(str(e), 404)
        except Exception as e:
            self.logger.error(f"Error pinging agent {agent_id}: {e}")
            return self._error_response("Failed to ping agent", 500)

