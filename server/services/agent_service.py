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
        self.model = agent_model
        self.db = db
        self.socketio = socketio
        self.users_collection = db.users
        self.commands_collection = db.agent_commands
        self.inactive_threshold = 5  # minutes
    
    def register_agent(self, agent_data: Dict, client_ip: str) -> Dict:
        """Register a new agent with user creation"""
        try:
            agent_id = agent_data.get("agent_id", str(uuid.uuid4()))
            hostname = agent_data.get("hostname")
            
            if not hostname:
                raise ValueError("Hostname is required")
            
            # Create/update user record
            user_data = {
                "user_id": client_ip,
                "hostname": hostname,
                "ip_address": client_ip,
                "platform": agent_data.get("platform"),
                "os_info": agent_data.get("os_info"),
                "agent_version": agent_data.get("agent_version"),
                "role": "agent",
                "status": "active",
                "last_heartbeat": datetime.utcnow(),
                "last_seen": datetime.utcnow(),
                "agent_token": secrets.token_hex(32)
            }
            
            # Check if user exists
            existing_user = self.users_collection.find_one({"user_id": client_ip, "role": "agent"})
            
            if existing_user:
                # Keep existing token if available
                if "agent_token" in existing_user:
                    user_data["agent_token"] = existing_user["agent_token"]
                user_data["created_at"] = existing_user.get("created_at")
                
                self.users_collection.update_one(
                    {"user_id": client_ip, "role": "agent"},
                    {"$set": user_data}
                )
                self.logger.info(f"Updated existing user for agent: {hostname}")
            else:
                user_data["created_at"] = datetime.utcnow()
                self.users_collection.insert_one(user_data)
                self.logger.info(f"Created new user for agent: {hostname}")
            
            # Register agent using model
            agent_registration_data = {
                "agent_id": agent_id,
                "user_id": client_ip,
                "hostname": hostname,
                "ip_address": client_ip,
                "mac_address": agent_data.get("mac_address"),
                "platform": agent_data.get("platform"),
                "os_info": agent_data.get("os_info"),
                "agent_version": agent_data.get("agent_version"),
                "agent_token": user_data["agent_token"]
            }
            
            agent_record = self.model.register_agent(agent_registration_data)
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("agent_registered", {
                    "agent_id": agent_id,
                    "hostname": hostname,
                    "ip_address": client_ip,
                    "status": "active",
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            return {
                "agent_id": agent_id,
                "user_id": client_ip,
                "token": user_data["agent_token"],
                "status": "active",
                "message": "Agent registered successfully",
                "server_time": datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error registering agent: {e}")
            raise
    
    def process_heartbeat(self, agent_id: str, token: str, heartbeat_data: Dict, client_ip: str) -> Dict:
        """Process agent heartbeat"""
        try:
            # Validate agent using model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            current_time = datetime.utcnow()
            
            # Update user record
            user_update = {
                "last_heartbeat": current_time,
                "last_seen": current_time,
                "status": heartbeat_data.get("status", "active"),
                "hostname": heartbeat_data.get("hostname", agent.get("hostname")),
                "platform": heartbeat_data.get("platform", agent.get("platform"))
            }
            
            self.users_collection.update_one(
                {"user_id": client_ip, "role": "agent"},
                {"$set": user_update},
                upsert=True
            )
            
            # Update agent record using model
            heartbeat_data["client_ip"] = client_ip
            self.model.update_heartbeat(agent_id, heartbeat_data)
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("agent_heartbeat", {
                    "agent_id": agent_id,
                    "hostname": agent.get("hostname"),
                    "status": heartbeat_data.get("status", "active"),
                    "timestamp": current_time.isoformat()
                })
            
            return {
                "status": "success",
                "message": "Heartbeat received",
                "server_time": current_time.isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Error processing heartbeat for agent {agent_id}: {e}")
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
            
            # Get agents from model
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
                    "user_id": agent.get("user_id")
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
            # Get agent from model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            current_time = datetime.utcnow()
            
            # Calculate status
            reported_status = agent.get("status", "unknown")
            actual_status = reported_status
            time_since_heartbeat = None
            
            if agent.get("last_heartbeat"):
                time_since_heartbeat = (current_time - agent["last_heartbeat"]).total_seconds() / 60
                if time_since_heartbeat > self.inactive_threshold:
                    actual_status = "inactive"
                else:
                    actual_status = "active"
            else:
                actual_status = "offline"
            
            # Get recent commands from database
            recent_commands = list(self.commands_collection.find(
                {"agent_id": agent_id}
            ).sort("created_at", -1).limit(10))
            
            # Format commands
            commands = []
            for cmd in recent_commands:
                cmd_data = {
                    "command_id": str(cmd["_id"]),
                    "command_type": cmd.get("command_type"),
                    "status": cmd.get("status"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None,
                    "completed_at": cmd.get("completed_at").isoformat() if cmd.get("completed_at") else None
                }
                commands.append(cmd_data)
            
            # Format agent data
            agent_data = {
                "agent_id": agent.get("agent_id"),
                "hostname": agent.get("hostname"),
                "ip_address": agent.get("ip_address"),
                "mac_address": agent.get("mac_address"),
                "platform": agent.get("platform"),
                "os_info": agent.get("os_info"),
                "agent_version": agent.get("agent_version"),
                "reported_status": reported_status,
                "status": actual_status,
                "registered_date": agent.get("registered_date").isoformat() if agent.get("registered_date") else None,
                "last_heartbeat": agent.get("last_heartbeat").isoformat() if agent.get("last_heartbeat") else None,
                "updated_date": agent.get("updated_date").isoformat() if agent.get("updated_date") else None,
                "last_heartbeat_ip": agent.get("last_heartbeat_ip"),
                "time_since_heartbeat": time_since_heartbeat,
                "metrics": agent.get("metrics"),
                "recent_commands": commands
            }
            
            return agent_data
            
        except Exception as e:
            self.logger.error(f"Error getting agent details for {agent_id}: {e}")
            raise
    
    def delete_agent(self, agent_id: str) -> bool:
        """Delete an agent and related data"""
        try:
            # Check if agent exists using model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Agent not found")
            
            # Delete related commands from database
            deleted_commands = self.commands_collection.delete_many({"agent_id": agent_id})
            self.logger.info(f"Deleted {deleted_commands.deleted_count} commands for agent {agent_id}")
            
            # Delete from users collection if exists
            deleted_users = self.users_collection.delete_many({
                "user_id": agent.get("user_id"), 
                "role": "agent"
            })
            self.logger.info(f"Deleted {deleted_users.deleted_count} user records for agent {agent_id}")
            
            # Delete agent using model
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
    
    def send_command(self, agent_id: str, command_data: Dict, created_by: str = "admin") -> str:
        """Send command to agent"""
        try:
            # Validate agent using model
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
            # Validate agent using model
            agent = self.model.find_by_agent_id(agent_id)
            if not agent:
                raise ValueError("Unknown agent")
            
            if agent.get("agent_token") != token:
                raise ValueError("Invalid token")
            
            # Update heartbeat using model
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
    
    def list_commands(self, filters: Dict = None, limit: int = 100, skip: int = 0) -> Dict:
        """List commands with filtering"""
        try:
            query = filters or {}
            
            # Get commands from database
            cursor = self.commands_collection.find(query).sort("created_at", -1).skip(skip).limit(limit)
            total_count = self.commands_collection.count_documents(query)
            
            # Format results
            commands = []
            for cmd in cursor:
                cmd_data = {
                    "command_id": str(cmd["_id"]),
                    "agent_id": cmd.get("agent_id"),
                    "command_type": cmd.get("command_type"),
                    "status": cmd.get("status"),
                    "created_at": cmd.get("created_at").isoformat() if cmd.get("created_at") else None,
                    "created_by": cmd.get("created_by"),
                    "parameters": cmd.get("parameters"),
                    "priority": cmd.get("priority")
                }
                commands.append(cmd_data)
            
            return {
                "commands": commands,
                "total": total_count
            }
            
        except Exception as e:
            self.logger.error(f"Error listing commands: {e}")
            return {
                "commands": [],
                "total": 0,
                "error": str(e)
            }
    
    def update_command_result(self, agent_id: str, token: str, command_id: str, 
                            status: str, result: str = None, execution_time: float = None):
        """Update command execution result"""
        try:
            # Validate agent using model
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
    
    def broadcast_command(self, command_data: Dict, created_by: str = "admin") -> Dict:
        """Broadcast command to multiple agents"""
        try:
            # Build agent filter
            agent_filter = command_data.get('filter', {})
            
            # Get matching agents using model
            agents = self.model.get_all_agents(agent_filter)
            if not agents:
                raise ValueError("No agents found")
            
            # Send command to each agent
            command_ids = []
            successful_count = 0
            
            for agent in agents:
                try:
                    command_id = self.send_command(agent['agent_id'], command_data, created_by)
                    command_ids.append(command_id)
                    successful_count += 1
                except Exception as e:
                    self.logger.warning(f"Failed to send command to agent {agent['agent_id']}: {e}")
                    continue
            
            # Emit SocketIO event
            if self.socketio:
                self.socketio.emit("commands_broadcast", {
                    "command_type": command_data["command_type"],
                    "agent_count": len(agents),
                    "successful_count": successful_count,
                    "created_by": created_by,
                    "timestamp": datetime.utcnow().isoformat()
                })
            
            return {
                "command_ids": command_ids,
                "agent_count": len(agents),
                "successful_count": successful_count
            }
            
        except Exception as e:
            self.logger.error(f"Error broadcasting command: {e}")
            raise
    
    def get_statistics(self) -> Dict:
        """Get agent statistics"""
        try:
            # Get statistics from model
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