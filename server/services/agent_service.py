"""
Agent Service - Business logic for agent operations
"""

import uuid
import secrets
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from bson import ObjectId
from models.agent_model import AgentModel

class AgentService:
    """Service class for agent business logic"""
    
    def __init__(self, agent_model: AgentModel, db, socketio=None):
        self.logger = logging.getLogger(self.__class__.__name__)
        self.model = agent_model  # ✅ Only use agent_model
        self.db = db
        self.socketio = socketio
        
        self.commands_collection = db.agent_commands
        self.inactive_threshold = 3  # minutes
    
    def register_agent(self, agent_data: Dict, client_ip: str) -> Dict:
        """Register a new agent using hostname+IP as identifier"""
        try:
            hostname = agent_data.get("hostname")
            
            self.logger.info(f"🔍 Agent registration: {hostname} from {client_ip}")
            
            if not hostname:
                raise ValueError("Hostname is required")
            
            # Use agent's reported IP if available
            agent_ip = agent_data.get("ip_address") or client_ip
            if agent_ip == "127.0.0.1" and client_ip != "127.0.0.1":
                agent_ip = client_ip
        
            # Check for existing agent by hostname + IP
            query = {"$or": [
                {"ip_address": agent_ip}, 
                {"hostname": hostname},
                {"$and": [{"hostname": hostname}, {"ip_address": agent_ip}]}
            ]}
            
            agents = self.model.get_all_agents(query, limit=1)
            existing_agent = agents[0] if agents else None
            
            if existing_agent:
                # Update existing agent
                agent_id = existing_agent.get("agent_id")
                update_data = {
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "platform": agent_data.get("platform"),
                    "os_info": agent_data.get("os_info"),
                    "agent_version": agent_data.get("agent_version"),
                    "last_heartbeat": datetime.utcnow(),
                    "updated_date": datetime.utcnow(),
                    "status": "active"
                }
                
                self.model.update_agent(agent_id, update_data)
                agent_token = existing_agent.get("agent_token")
                if not agent_token:
                    agent_token = secrets.token_hex(32)
                    self.model.update_agent(agent_id, {"agent_token": agent_token})
                
                self.logger.info(f"✅ Updated existing agent: {agent_id}")
            else:
                # Create new agent
                agent_id = str(uuid.uuid4())
                agent_token = secrets.token_hex(32)
                
                agent_registration_data = {
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "platform": agent_data.get("platform"),
                    "os_info": agent_data.get("os_info"),
                    "agent_version": agent_data.get("agent_version"),
                    "agent_token": agent_token
                }
                
                self.model.register_agent(agent_registration_data)
                self.logger.info(f"✅ Created new agent: {agent_id}")

            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("agent_registered", {
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": agent_ip,
                    "status": "active",
                    "timestamp": datetime.utcnow().isoformat()
                })
        
            return {
                "agent_id": agent_id,
                "user_id": agent_ip,
                "token": agent_token,
                "status": "active",
                "message": f"Agent {'updated' if existing_agent else 'registered'} successfully",
                "server_time": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            self.logger.error(f"Agent registration failed: {e}")
            raise
    
    def _calculate_agent_status(self, agent: Dict, current_time: datetime) -> str:
        """
        Calculate real-time agent status based on last heartbeat
        
        Status Logic:
        - active: Last heartbeat within 3 minutes
        - inactive: Last heartbeat 3-30 minutes ago
        - offline: Last heartbeat > 30 minutes ago or never
        """
        last_heartbeat = agent.get("last_heartbeat")
        
        if not last_heartbeat:
            return "offline"  # Never sent heartbeat
        
        # Calculate time difference in minutes
        time_diff = (current_time - last_heartbeat).total_seconds() / 60
        
        if time_diff <= self.inactive_threshold:  # 3 minutes
            return "active"
        elif time_diff <= (self.inactive_threshold * 10):  # 30 minutes
            return "inactive"
        else:
            return "offline"

    def process_heartbeat(self, agent_id: str, token: str, heartbeat_data: Dict, client_ip: str) -> Dict:
        """Process agent heartbeat with enhanced validation"""
        try:
            # Validate agent and token
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # Update heartbeat with comprehensive data
            update_data = {
                "client_ip": client_ip,
                "metrics": heartbeat_data.get("metrics", {}),
                "status": heartbeat_data.get("status", "active"),
                "agent_version": heartbeat_data.get("agent_version"),
                "last_heartbeat_data": heartbeat_data,
                "platform": heartbeat_data.get("platform"),
                "os_info": heartbeat_data.get("os_info")
            }
            
            success = self.model.update_heartbeat(agent_id, update_data)
            
            if not success:
                raise ValueError("Failed to update heartbeat")
            
            # Emit real-time status update
            if self.socketio:
                self.socketio.emit("agent_heartbeat", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "status": "active",
                    "last_heartbeat": datetime.utcnow().isoformat(),
                    "metrics": heartbeat_data.get("metrics", {}),
                    "client_ip": client_ip
                })
            
            self.logger.debug(f"✅ Heartbeat processed for agent: {agent_id}")
            
            return {
                "agent_id": agent_id,
                "status": "active",
                "next_heartbeat": int((datetime.utcnow().timestamp() + 60) * 1000),  # Next heartbeat time in ms
                "server_commands": [],  # TODO: Return pending commands
                "server_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Heartbeat processing failed: {e}")
            raise
    
    def get_agents(self, filters: Dict = None, limit: int = 100, skip: int = 0) -> Dict:
        """Get agents with filtering and status calculation"""
        try:
            # Build query for model
            query = {}
            if filters:
                if filters.get("status"):
                    status = filters["status"]
                    if status == "inactive":
                        inactive_threshold = datetime.utcnow() - timedelta(minutes=self.inactive_threshold)
                        query["last_heartbeat"] = {"$lt": inactive_threshold}
                    elif status == "active":
                        inactive_threshold = datetime.utcnow() - timedelta(minutes=self.inactive_threshold)
                        query["last_heartbeat"] = {"$gte": inactive_threshold}
                    else:
                        query["status"] = status
                
                if filters.get("hostname"):
                    query["hostname"] = {"$regex": filters["hostname"], "$options": "i"}
            
            # ✅ Get agents from model only
            agents = self.model.get_all_agents(query, limit, skip)
            total_count = self.model.count_agents(query)
            
            # Calculate actual status for each agent
            current_time = datetime.utcnow()
            agents_list = []
            
            for agent in agents:
                # Calculate actual status based on last_heartbeat
                reported_status = agent.get("status", "unknown")
                actual_status = reported_status
                
                if agent.get("last_heartbeat"):
                    time_since_heartbeat = (current_time - agent["last_heartbeat"]).total_seconds() / 60
                    if time_since_heartbeat > self.inactive_threshold:
                        actual_status = "inactive"
                    else:
                        actual_status = "active"
                else:
                    actual_status = "offline"
                
                # Format agent data
                agent_data = {
                    "agent_id": agent.get("agent_id"),
                    "hostname": agent.get("hostname", "Unknown"),
                    "ip_address": agent.get("ip_address", "Unknown"),
                    "platform": agent.get("platform", "Unknown"),
                    "os_info": agent.get("os_info", "Unknown"),
                    "agent_version": agent.get("agent_version", "Unknown"),
                    "reported_status": reported_status,
                    "status": actual_status,
                    "registered_date": agent.get("registered_date").isoformat() if agent.get("registered_date") else None,
                    "last_heartbeat": agent.get("last_heartbeat").isoformat() if agent.get("last_heartbeat") else None,
                    "metrics": agent.get("metrics"),
                    "user_id": agent.get("ip_address")  # Use IP as user_id for compatibility
                }
                
                agents_list.append(agent_data)
            
            return {
                "agents": agents_list,
                "total": total_count,
                "success": True
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agents: {e}")
            return {
                "agents": [],
                "total": 0,
                "success": False,
                "error": str(e)
            }
    
    def get_agent_details(self, agent_id: str) -> Dict:
        """Get detailed agent information"""
        try:
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            current_time = datetime.utcnow()
            
            # Calculate status
            actual_status = "offline"
            time_since_heartbeat = None
            
            if agent.get("last_heartbeat"):
                time_since_heartbeat = (current_time - agent["last_heartbeat"]).total_seconds() / 60
                actual_status = "active" if time_since_heartbeat <= self.inactive_threshold else "inactive"
            
            # Get recent commands
            recent_commands = list(self.commands_collection.find(
                {"agent_id": agent_id}
            ).sort("created_at", -1).limit(5))
            
            commands = []
            for cmd in recent_commands:
                commands.append({
                    "command_id": str(cmd["_id"]),
                    "command_type": cmd.get("command_type"),
                    "status": cmd.get("status"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None
                })
            
            return {
                "agent_id": agent.get("agent_id"),
                "hostname": agent.get("hostname"),
                "ip_address": agent.get("ip_address"),
                "mac_address": agent.get("mac_address"),
                "platform": agent.get("platform"),
                "os_info": agent.get("os_info"),
                "agent_version": agent.get("agent_version"),
                "status": actual_status,
                "registered_date": agent.get("registered_date").isoformat() if agent.get("registered_date") else None,
                "last_heartbeat": agent.get("last_heartbeat").isoformat() if agent.get("last_heartbeat") else None,
                "time_since_heartbeat": time_since_heartbeat,
                "recent_commands": commands
            }
            
        except Exception as e:
            self.logger.error(f"Error getting agent details: {e}")
            raise
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent and related data"""
        try:
            # ✅ Check if agent exists using model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Delete related commands from database
            deleted_commands = self.commands_collection.delete_many({"agent_id": agent_id})
            self.logger.info(f"Deleted {deleted_commands.deleted_count} commands for agent {agent_id}")
            
            # ✅ Delete agent using model
            success = self.model.delete_agent(agent_id)
            
            if success and self.socketio:
                self.socketio.emit("agent_deleted", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            return success
            
        except Exception as e:
            self.logger.error(f"Error deleting agent {agent_id}: {e}")
            raise
    
    def get_statistics(self) -> Dict:
        """Get agent statistics"""
        try:
            # ✅ Get statistics from model
            return self.model.get_agent_statistics(self.inactive_threshold)
        except Exception as e:
            self.logger.error(f"Error getting agent statistics: {e}")
            return {"total": 0, "active": 0, "inactive": 0, "offline": 0}
    
    def get_active_count(self) -> int:
        """Get count of active agents"""
        try:
            inactive_threshold = datetime.utcnow() - timedelta(minutes=self.inactive_threshold)
            return self.model.collection.count_documents({
                "last_heartbeat": {"$gte": inactive_threshold}
            })
        except Exception as e:
            self.logger.error(f"Error getting active agent count: {e}")
            return 0

    # ✅ Keep other methods but remove user_collection dependencies
    def send_command(self, agent_id: str, command_data: Dict, created_by: str = "admin") -> str:
        """Send command to agent"""
        try:
            # ✅ Validate agent using model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Check if agent is active
            if agent.get("last_heartbeat"):
                time_since_heartbeat = (datetime.utcnow() - agent["last_heartbeat"]).total_seconds() / 60
                if time_since_heartbeat > self.inactive_threshold:
                    raise ValueError("Agent is inactive")
            
            # Create command in database
            command = {
                "agent_id": agent_id,
                "command_type": command_data["command_type"],
                "parameters": command_data.get("parameters", {}),
                "priority": command_data.get("priority", 1),
                "description": command_data.get("description", ""),
                "status": "pending",
                "created_by": created_by,
                "created_at": datetime.utcnow()
            }
            
            result = self.commands_collection.insert_one(command)
            command_id = str(result.inserted_id)
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("command_created", {
                    "command_id": command_id,
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "command_type": command_data["command_type"],
                    "created_by": created_by,
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            self.logger.info(f"Command {command_id} sent to agent {agent_id}")
            return command_id
            
        except Exception as e:
            self.logger.error(f"Error sending command to agent {agent_id}: {e}")
            raise

    def get_pending_commands(self, agent_id: str, token: str) -> Dict:
        """Get pending commands for agent"""
        try:
            # ✅ Validate agent using model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # ✅ Update heartbeat using model
            self.model.update_heartbeat(agent_id, {"client_ip": "heartbeat_via_commands"})
            
            # Get pending commands from database
            commands = list(self.commands_collection.find({
                "agent_id": agent_id,
                "status": "pending"
            }).sort("priority", -1).sort("created_at", 1))
            
            # Format commands
            command_list = []
            for cmd in commands:
                cmd_data = {
                    "command_id": str(cmd["_id"]),
                    "command_type": cmd.get("command_type"),
                    "parameters": cmd.get("parameters"),
                    "priority": cmd.get("priority"),
                    "description": cmd.get("description"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None
                }
                command_list.append(cmd_data)
            
            return {
                "commands": command_list,
                "count": len(command_list),
                "server_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error getting pending commands for agent {agent_id}: {e}")
            raise

    def update_command_result(self, agent_id: str, token: str, command_id: str, 
                            status: str, result: str = None, execution_time: float = None):
        """Update command execution result"""
        try:
            # ✅ Validate agent using model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # Validate command
            try:
                command_object_id = ObjectId(command_id)
            except:
                raise ValueError("Invalid command ID format")
            
            command = self.commands_collection.find_one({"_id": command_object_id})
            if not command:
                raise ValueError("Command not found")
            
            if command.get("agent_id") != agent_id:
                raise ValueError("Command does not belong to this agent")
            
            # Update command status in database
            update_data = {
                "status": status,
                "completed_at": datetime.utcnow(),
                "result": result,
                "execution_time": execution_time
            }
            
            self.commands_collection.update_one(
                {"_id": command_object_id},
                {"$set": update_data}
            )
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("command_status_update", {
                    "command_id": command_id,
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "status": status,
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            self.logger.info(f"Command {command_id} status updated to {status}")
            
        except Exception as e:
            self.logger.error(f"Error updating command result: {e}")
            raise